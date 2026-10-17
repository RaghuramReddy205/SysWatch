#!/usr/bin/env python3
"""SysWatch - System Resource Alert & Notification System (backend).

Monitors CPU, memory, disk and process usage of the machine it runs on,
raises alerts when thresholds are exceeded, and keeps user accounts
(password stored as a salted hash) in a local SQLite database.
"""
import contextlib
import datetime
import os
import platform
import re
import secrets
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from collections import deque
from functools import wraps

import psutil
from flask import Flask, jsonify, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("SYSWATCH_DB", os.path.join(BASE, "monitor.db"))
SAMPLE_EVERY = 2.0      # seconds between samples
COOLDOWN = 60           # seconds before the same alert may fire again
HISTORY_LEN = 60        # samples kept for the live chart

DEFAULTS = {
    "cpu": 85,              # % total CPU
    "memory": 85,           # % RAM
    "disk": 90,             # % of any partition
    "process_cpu": 60,      # % of total CPU used by a single process
    "process_memory": 30,   # % of RAM used by a single process
    "process_count": 800,   # number of running processes
}
LIMITS = {  # allowed (min, max) per threshold
    "cpu": (10, 100), "memory": (10, 100), "disk": (10, 100),
    "process_cpu": (5, 100), "process_memory": (5, 100),
    "process_count": (20, 20000),
}

# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
@contextlib.contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def now_iso():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def init_db():
    with db() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_login TEXT
            );
            CREATE TABLE IF NOT EXISTS alerts(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                level TEXT NOT NULL,
                metric TEXT NOT NULL,
                value REAL,
                threshold REAL,
                message TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS settings(
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        for k, v in DEFAULTS.items():
            c.execute("INSERT OR IGNORE INTO settings VALUES(?,?)", (k, str(v)))
        c.execute("INSERT OR IGNORE INTO settings VALUES('secret_key',?)",
                  (secrets.token_hex(32),))


THRESH = dict(DEFAULTS)
THRESH_LOCK = threading.Lock()


def load_thresholds():
    with db() as c:
        rows = c.execute("SELECT key,value FROM settings").fetchall()
    with THRESH_LOCK:
        for r in rows:
            if r["key"] in DEFAULTS:
                THRESH[r["key"]] = int(float(r["value"]))


# --------------------------------------------------------------------------
# Host information (adapts to whichever machine this runs on)
# --------------------------------------------------------------------------
def cpu_model():
    try:
        if sys.platform.startswith("linux"):
            with open("/proc/cpuinfo") as f:
                lines = f.read().splitlines()
            for key in ("model name", "hardware", "cpu model", "processor model"):
                for line in lines:
                    if line.lower().startswith(key) and ":" in line:
                        return line.split(":", 1)[1].strip()
        elif sys.platform == "darwin":
            return subprocess.check_output(
                ["sysctl", "-n", "machdep.cpu.brand_string"], text=True, timeout=3).strip()
        elif sys.platform == "win32":
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
            return winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
    except Exception:
        pass
    return platform.processor() or platform.machine() or "Unknown CPU"


def os_info():
    system = platform.system()
    if system == "Linux":
        name = "Linux"
        try:
            name = platform.freedesktop_os_release().get("PRETTY_NAME", name)
        except Exception:
            pass
        return "Linux", name
    if system == "Darwin":
        return "macOS", "macOS " + platform.mac_ver()[0]
    if system == "Windows":
        return "Windows", f"Windows {platform.release()} ({platform.version()})"
    return system or "Unknown", f"{system} {platform.release()}"


def host_info():
    family, pretty = os_info()
    boot = psutil.boot_time()
    freq = None
    try:
        f = psutil.cpu_freq()
        freq = f.max or f.current if f else None
    except Exception:
        pass
    addrs = []
    try:
        for iface, lst in psutil.net_if_addrs().items():
            for a in lst:
                if a.family == socket.AF_INET and not a.address.startswith("127."):
                    addrs.append({"iface": iface, "ip": a.address})
    except Exception:
        pass
    battery = None
    try:
        b = psutil.sensors_battery()
        if b:
            battery = {"percent": round(b.percent, 1), "plugged": bool(b.power_plugged)}
    except Exception:
        pass
    temps = None
    try:
        if hasattr(psutil, "sensors_temperatures"):
            t = psutil.sensors_temperatures()
            flat = [e.current for lst in t.values() for e in lst if e.current]
            if flat:
                temps = {"max": round(max(flat), 1), "avg": round(sum(flat) / len(flat), 1)}
    except Exception:
        pass
    users = []
    try:
        users = sorted({u.name for u in psutil.users()})
    except Exception:
        pass
    swap_total = 0
    try:
        swap_total = psutil.swap_memory().total
    except Exception:
        pass
    return {
        "hostname": socket.gethostname(),
        "os_family": family,
        "os_name": pretty,
        "kernel": platform.release(),
        "arch": platform.machine(),
        "cpu_model": cpu_model(),
        "physical_cores": psutil.cpu_count(logical=False),
        "logical_cores": psutil.cpu_count(logical=True),
        "cpu_max_mhz": round(freq) if freq else None,
        "ram_total": psutil.virtual_memory().total,
        "swap_total": swap_total,
        "boot_time": boot,
        "python": platform.python_version(),
        "addresses": addrs,
        "battery": battery,
        "temperatures": temps,
        "logged_in_users": users,
        "has_load_avg": hasattr(os, "getloadavg"),
    }


# --------------------------------------------------------------------------
# Sampling + alerting
# --------------------------------------------------------------------------
LOCK = threading.Lock()
SNAP = {}
HISTORY = deque(maxlen=HISTORY_LEN)
ACTIVE = []                 # currently breached thresholds
ACTIVE_PREV = {}            # key -> label of breaches in the previous sample
LAST_ALERT = {}             # key -> last time an alert fired
SKIP_FS = {"squashfs", "iso9660", "udf", "cdfs", "autofs"}
_net_prev = {"io": None, "t": None}


def add_alert(level, metric, value, threshold, message):
    with db() as c:
        c.execute(
            "INSERT INTO alerts(ts,level,metric,value,threshold,message) VALUES(?,?,?,?,?,?)",
            (now_iso(), level, metric, value, threshold, message))
        c.execute("DELETE FROM alerts WHERE id NOT IN "
                  "(SELECT id FROM alerts ORDER BY id DESC LIMIT 500)")
    print(f"[{level.upper():8}] {message}", flush=True)


def severity(value, limit, is_percent=True):
    if is_percent:
        return "critical" if value >= limit + (100 - limit) * 0.5 else "warning"
    return "critical" if value >= limit * 1.25 else "warning"


def evaluate(snap):
    global ACTIVE, ACTIVE_PREV
    with THRESH_LOCK:
        th = dict(THRESH)
    now = time.time()
    checks = [
        ("cpu", "CPU", "CPU usage", snap["cpu"]["percent"], "%", "cpu", True, ""),
        ("memory", "Memory", "Memory usage", snap["memory"]["percent"], "%", "memory", True, ""),
        ("process_count", "Processes", "Process count", snap["processes"]["count"], "", "process_count", False, ""),
    ]
    for p in snap["disk"]["partitions"]:
        checks.append((f"disk:{p['mount']}", "Disk", f"Disk {p['mount']}", p["percent"], "%", "disk", True, ""))
    procs = snap["processes"]["top"]
    if procs:
        tc = max(procs, key=lambda x: x["cpu"])
        tm = max(procs, key=lambda x: x["mem"])
        checks.append(("process_cpu", "Process CPU", f"Process '{tc['name']}' (PID {tc['pid']}) CPU",
                       tc["cpu"], "%", "process_cpu", True, ""))
        checks.append(("process_memory", "Process memory", f"Process '{tm['name']}' (PID {tm['pid']}) memory",
                       tm["mem"], "%", "process_memory", True, ""))

    active, current = [], {}
    for key, metric, label, value, unit, tkey, pct, _ in checks:
        limit = th[tkey]
        if value >= limit:
            level = severity(value, limit, pct)
            current[key] = label
            active.append({"key": key, "metric": metric, "label": label, "value": round(value, 1),
                           "threshold": limit, "unit": unit, "level": level})
            if now - LAST_ALERT.get(key, 0) >= COOLDOWN:
                LAST_ALERT[key] = now
                add_alert(level, metric, round(value, 1), limit,
                          f"{label} is {round(value, 1)}{unit} (threshold {limit}{unit})")
    for key, label in ACTIVE_PREV.items():
        if key not in current:
            LAST_ALERT.pop(key, None)
            add_alert("info", "Recovery", None, None, f"{label} is back below its threshold")
    ACTIVE_PREV = current
    return active


def take_sample():
    cores = psutil.cpu_count() or 1
    per = psutil.cpu_percent(interval=None, percpu=True)
    total = sum(per) / len(per) if per else 0.0

    freq = None
    try:
        f = psutil.cpu_freq()
        freq = round(f.current) if f else None
    except Exception:
        pass
    load = list(os.getloadavg()) if hasattr(os, "getloadavg") else None

    vm = psutil.virtual_memory()
    try:
        sw = psutil.swap_memory()
        swap = {"percent": sw.percent, "used": sw.used, "total": sw.total}
    except Exception:
        swap = {"percent": 0, "used": 0, "total": 0}

    parts, seen = [], set()
    for p in psutil.disk_partitions(all=False):
        if p.fstype.lower() in SKIP_FS or p.fstype == "" or "cdrom" in p.opts \
                or p.device.startswith("/dev/loop"):
            continue
        try:
            u = psutil.disk_usage(p.mountpoint)
        except Exception:
            continue
        sig = (p.device, u.total)
        if u.total == 0 or sig in seen:
            continue
        seen.add(sig)
        parts.append({"mount": p.mountpoint, "device": p.device, "fstype": p.fstype,
                      "total": u.total, "used": u.used, "percent": round(u.percent, 1)})
    disk_pct = max((x["percent"] for x in parts), default=0)

    procs = []
    for p in psutil.process_iter(["pid", "name", "username", "status", "cpu_percent", "memory_percent"]):
        i = p.info
        if i["pid"] == 0:
            continue
        procs.append({
            "pid": i["pid"], "name": i["name"] or "?", "user": i["username"] or "",
            "status": i["status"] or "",
            "cpu": round((i["cpu_percent"] or 0) / cores, 1),
            "mem": round(i["memory_percent"] or 0, 1),
        })
    by_cpu = sorted(procs, key=lambda x: x["cpu"], reverse=True)[:15]
    by_mem = sorted(procs, key=lambda x: x["mem"], reverse=True)[:15]
    top = {x["pid"]: x for x in by_cpu + by_mem}.values()

    net = {"sent": 0, "recv": 0, "sent_rate": 0, "recv_rate": 0}
    try:
        io, t = psutil.net_io_counters(), time.time()
        net["sent"], net["recv"] = io.bytes_sent, io.bytes_recv
        if _net_prev["io"]:
            dt = max(t - _net_prev["t"], 0.001)
            net["sent_rate"] = max(0, (io.bytes_sent - _net_prev["io"].bytes_sent) / dt)
            net["recv_rate"] = max(0, (io.bytes_recv - _net_prev["io"].bytes_recv) / dt)
        _net_prev["io"], _net_prev["t"] = io, t
    except Exception:
        pass

    snap = {
        "ts": time.time(),
        "cpu": {"percent": round(total, 1), "per_core": [round(x, 1) for x in per],
                "freq_mhz": freq, "load_avg": load},
        "memory": {"percent": vm.percent, "used": vm.total - vm.available, "total": vm.total,
                   "available": vm.available, "swap": swap},
        "disk": {"percent": disk_pct, "partitions": parts},
        "processes": {"count": len(procs), "top": list(top)},
        "network": net,
    }
    return snap


def sampler():
    # prime psutil's CPU counters so the first real sample is meaningful
    psutil.cpu_percent(interval=None, percpu=True)
    for p in psutil.process_iter():
        with contextlib.suppress(Exception):
            p.cpu_percent(None)
    time.sleep(1)
    global ACTIVE
    while True:
        try:
            snap = take_sample()
            active = evaluate(snap)
            with LOCK:
                SNAP.clear()
                SNAP.update(snap)
                ACTIVE = active
                HISTORY.append({"t": snap["ts"], "cpu": snap["cpu"]["percent"],
                                "mem": snap["memory"]["percent"], "disk": snap["disk"]["percent"]})
        except Exception as e:  # keep the monitor alive no matter what
            print("sampler error:", repr(e), flush=True)
        time.sleep(SAMPLE_EVERY)


# --------------------------------------------------------------------------
# Web app
# --------------------------------------------------------------------------
app = Flask(__name__, static_folder=os.path.join(BASE, "static"), static_url_path="/static")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  PERMANENT_SESSION_LIFETIME=datetime.timedelta(days=7))


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if "uid" not in session:
            return jsonify(error="Not signed in"), 401
        return fn(*a, **kw)
    return wrapper


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


USER_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


@app.post("/api/register")
def register():
    d = request.get_json(silent=True) or {}
    u, pw = (d.get("username") or "").strip(), d.get("password") or ""
    if not USER_RE.match(u):
        return jsonify(error="Username must be 3-32 characters: letters, numbers, . _ -"), 400
    if len(pw) < 6:
        return jsonify(error="Password must be at least 6 characters"), 400
    try:
        with db() as c:
            cur = c.execute(
                "INSERT INTO users(username,password_hash,created_at,last_login) VALUES(?,?,?,?)",
                (u, generate_password_hash(pw, method="pbkdf2:sha256"), now_iso(), now_iso()))
            uid = cur.lastrowid
    except sqlite3.IntegrityError:
        return jsonify(error="That username is already taken"), 409
    session.permanent = True
    session["uid"], session["username"] = uid, u
    return jsonify(ok=True, username=u)


@app.post("/api/login")
def login():
    d = request.get_json(silent=True) or {}
    u, pw = (d.get("username") or "").strip(), d.get("password") or ""
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if not row or not check_password_hash(row["password_hash"], pw):
            time.sleep(0.5)  # slow down guessing
            return jsonify(error="Invalid username or password"), 401
        c.execute("UPDATE users SET last_login=? WHERE id=?", (now_iso(), row["id"]))
    session.permanent = True
    session["uid"], session["username"] = row["id"], row["username"]
    return jsonify(ok=True, username=row["username"])


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    if "uid" not in session:
        return jsonify(authenticated=False)
    return jsonify(authenticated=True, username=session["username"])


@app.get("/api/system")
@login_required
def system():
    return jsonify(host_info())


@app.get("/api/metrics")
@login_required
def metrics():
    with LOCK:
        snap, hist, active = dict(SNAP), list(HISTORY), list(ACTIVE)
    with db() as c:
        rows = c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 40").fetchall()
    with THRESH_LOCK:
        th = dict(THRESH)
    return jsonify({**snap, "history": hist, "active": active, "thresholds": th,
                    "alerts": [dict(r) for r in rows], "ready": bool(snap)})


@app.post("/api/thresholds")
@login_required
def set_thresholds():
    d = request.get_json(silent=True) or {}
    new = {}
    for k, (lo, hi) in LIMITS.items():
        if k in d:
            try:
                v = int(d[k])
            except (TypeError, ValueError):
                return jsonify(error=f"Invalid value for {k}"), 400
            if not lo <= v <= hi:
                return jsonify(error=f"{k} must be between {lo} and {hi}"), 400
            new[k] = v
    with db() as c:
        for k, v in new.items():
            c.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (k, str(v)))
    load_thresholds()
    return jsonify(ok=True)


@app.post("/api/alerts/clear")
@login_required
def clear_alerts():
    with db() as c:
        c.execute("DELETE FROM alerts")
    return jsonify(ok=True)


def main():
    init_db()
    load_thresholds()
    with db() as c:
        app.secret_key = c.execute("SELECT value FROM settings WHERE key='secret_key'").fetchone()[0]
    threading.Thread(target=sampler, daemon=True).start()
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5050"))
    print(f"SysWatch running on http://{host}:{port}  (database: {DB_PATH})", flush=True)
    app.run(host=host, port=port, threaded=True, debug=False)


if __name__ == "__main__":
    main()

# SysWatch
A monitoring system that tracks CPU, memory, disk and process usage and generates alerts when predefined thresholds are exceeded.
# SysWatch — System Resource Alert & Notification System

A 3D parallax web dashboard that monitors CPU, memory, disk and process usage of the
machine it runs on, and raises alerts when thresholds are exceeded.

## Run

```bash
pip install -r requirements.txt
python server.py          # Windows: py server.py
```

Open http://127.0.0.1:5050 and **Create account** on first use.

Options (environment variables): `HOST` (default `127.0.0.1`; use `0.0.0.0` to view from
another device on your network), `PORT` (default `5050`), `SYSWATCH_DB` (database path).

## Running on another machine

Copy this folder to the other machine and run the same commands. The Host section
automatically shows that machine's OS, CPU model, cores, RAM, swap, disks, IP addresses,
battery, temperatures, uptime and logged-in users. Features the OS doesn't provide
(for example load average on Windows) are reported as unavailable instead of failing.

## Login & storage

Accounts are stored in `monitor.db` (SQLite) next to `server.py`. Passwords are saved as
salted PBKDF2 hashes, not plain text. The same database keeps alert history and thresholds.

## Alerts

Defaults: CPU 85%, memory 85%, disk 90%, single process CPU 60%, single process memory 30%,
process count 800. Change them in the Thresholds section. Each breach raises a toast,
an optional beep, and a stored alert (at most once a minute per metric), plus a
recovery notice when the value drops back.

## Files

- `server.py` — Flask API, psutil sampler, alert engine, SQLite
- `static/index.html` — login page and the 3D parallax dashboard

# Linux Security Log Analyzer v2

A lightweight Python CLI tool for authorized Linux security monitoring. It continuously follows an authentication log and prints a live alert whenever a failed SSH authentication event is detected.

## Features

- Continuous monitoring of `/var/log/auth.log`
- Detects common failed SSH authentication messages
- Shows timestamp, username, client IP, and client port
- Counts failed attempts per source IP
- Configurable alert threshold
- Standard Python library only — no `pip install` required
- Includes a safe sample log for testing the parser

## Requirements

- Python 3.9+
- Kali Linux, Ubuntu, Debian, or another Linux distribution using a compatible authentication log
- Permission to read the log file

## Quick Start

```bash
chmod +x log_monitor.py
sudo ./log_monitor.py
```

Or:

```bash
sudo python3 log_monitor.py
```

Custom threshold:

```bash
sudo python3 log_monitor.py --threshold 3
```

Custom log path:

```bash
sudo python3 log_monitor.py --file /path/to/auth.log
```

## How It Works

The monitor starts at the current end of the selected log file and waits for new lines. When a new SSH failure is detected, it prints the event and updates the failure count for that source IP.

This tool does **not** perform login attempts, scanning, blocking, or exploitation. It is intended for defensive monitoring of systems you are authorized to administer.

## Example Output

```text
===============================================================================
 LIVE LINUX SSH SECURITY LOG MONITOR v2
===============================================================================
Monitoring : /var/log/auth.log
Alert threshold: 5 failed attempts from one IP
Press Ctrl+C to stop.

[SSH FAILED LOGIN]
Time      : Sep  7 23:10:01
Username  : admin
Client IP : 192.168.1.25
Port      : 44221
Attempts  : 1
--------------------------------------------------
```

## Project Structure

```text
linux-security-log-analyzer-v2/
├── log_monitor.py
├── sample_auth.log
├── tests/
│   └── test_log_monitor.py
├── .gitignore
├── LICENSE
└── README.md
```

## Testing

Run the unit test:

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT License. See `LICENSE`.

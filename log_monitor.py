#!/usr/bin/env python3
"""Linux Security Log Analyzer v2: live SSH failure monitor."""
import argparse
import re
import time
from collections import Counter

IP_RE = r"(?:\d{1,3}\.){3}\d{1,3}"
USER_RE = r"failed password for (?:invalid user )?([A-Za-z0-9_.@+-]+)"


def extract_event(line):
    low = line.lower()
    if "sshd" not in low:
        return None
    if not any(x in low for x in ("failed password", "authentication failure", "failed publickey")):
        return None
    ip_match = re.search(IP_RE, line)
    ip = ip_match.group(0) if ip_match else "UNKNOWN"
    user = "UNKNOWN"
    m = re.search(USER_RE, line, re.I)
    if m:
        user = m.group(1)
    port_match = re.search(r"\bport\s+(\d{1,5})\b", line, re.I)
    port = port_match.group(1) if port_match else "N/A"
    return {"timestamp": line[:15].strip(), "user": user, "ip": ip, "port": port}


def monitor(path, threshold):
    counts = Counter()
    print("=" * 78)
    print(" LIVE LINUX SSH SECURITY LOG MONITOR v2")
    print("=" * 78)
    print(f"Monitoring: {path}")
    print(f"Alert threshold: {threshold} failed attempts from one IP")
    print("Press Ctrl+C to stop.\n")

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(0, 2)  # only monitor new entries
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                event = extract_event(line)
                if not event:
                    continue
                counts[event["ip"]] += 1
                count = counts[event["ip"]]
                print("\n[⚠ SSH FAILED LOGIN]")
                print(f"Time      : {event['timestamp']}")
                print(f"Username  : {event['user']}")
                print(f"Client IP : {event['ip']}")
                print(f"Port      : {event['port']}")
                print(f"Attempts  : {count}")
                if count >= threshold:
                    print(f"ALERT     : {event['ip']} reached {count} failed SSH attempts!")
                print("-" * 50, flush=True)
    except PermissionError:
        print("Permission denied. Run with: sudo python3 log_monitor.py")
    except FileNotFoundError:
        print(f"Log file not found: {path}")
        print("On some Linux systems the file may be /var/log/secure, or SSH logs may be in journald.")
    except KeyboardInterrupt:
        print("\nMonitor stopped.")


def main():
    parser = argparse.ArgumentParser(description="Continuously monitor Linux SSH authentication failures.")
    parser.add_argument("-f", "--file", default="/var/log/auth.log", help="Authentication log path")
    parser.add_argument("-t", "--threshold", type=int, default=5, help="Alert after this many failures from one IP")
    args = parser.parse_args()
    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    monitor(args.file, args.threshold)


if __name__ == "__main__":
    main()

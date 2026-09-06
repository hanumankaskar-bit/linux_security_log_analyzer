import os
import sys
import unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import log_monitor

class TestLogMonitor(unittest.TestCase):
    def test_failed_password(self):
        line = "Sep  7 23:10:01 kali sshd[1234]: Failed password for admin from 192.168.1.25 port 44221 ssh2"
        event = log_monitor.extract_event(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["user"], "admin")
        self.assertEqual(event["ip"], "192.168.1.25")
        self.assertEqual(event["port"], "44221")

    def test_non_ssh_line_is_ignored(self):
        self.assertIsNone(log_monitor.extract_event("Sep 7 systemd: service started"))

if __name__ == "__main__":
    unittest.main()

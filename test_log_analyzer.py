import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCRIPT = Path(__file__).with_name("log_analyzer.py")


class TestLogAnalyzer(unittest.TestCase):
    def run_analyzer(self, content):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "test.jsonl"
            log_file.write_text(content, encoding="utf-8")

            return subprocess.run(
                [sys.executable, str(SCRIPT), str(log_file)],
                capture_output=True,
                text=True,
                check=False,
            )

    def make_event(self, timestamp, source_ip, path):
        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "method": "GET",
            "path": path,
            "status": 200,
        }

    def test_reconnaissance_within_five_minutes(self):
        start = datetime(2026, 10, 28, 20, 0, tzinfo=timezone.utc)
        paths = ["/", "/admin", "/api", "/health", "/robots.txt"]
        content = "".join(
            json.dumps(
                self.make_event(
                    (start + timedelta(seconds=i)).isoformat(),
                    "192.0.2.10",
                    path,
                )
            ) + "\n"
            for i, path in enumerate(paths)
        )

        result = self.run_analyzer(content)
        self.assertEqual(result.returncode, 0)
        self.assertIn("[ALERT] Possible endpoint reconnaissance", result.stdout)

    def test_no_alert_when_paths_are_spread_out(self):
        start = datetime(2026, 10, 28, 20, 0, tzinfo=timezone.utc)
        paths = ["/", "/admin", "/api", "/health", "/robots.txt"]
        content = "".join(
            json.dumps(
                self.make_event(
                    (start + timedelta(minutes=2 * i)).isoformat(),
                    "192.0.2.20",
                    path,
                )
            ) + "\n"
            for i, path in enumerate(paths)
        )

        result = self.run_analyzer(content)
        self.assertEqual(result.returncode, 0)
        self.assertIn("[INFO] No reconnaissance threshold reached", result.stdout)

    def test_invalid_json_line_is_counted(self):
        event = self.make_event(
            "2026-10-28T20:00:00+00:00",
            "192.0.2.30",
            "/",
        )
        content = json.dumps(event) + "\n{invalid json}\n"

        result = self.run_analyzer(content)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Invalid JSON lines: 1", result.stdout)
        self.assertIn("Skipped invalid events: 0", result.stdout)

    def test_invalid_timestamp_is_skipped(self):
        event = self.make_event("not-a-timestamp", "192.0.2.40", "/")
        result = self.run_analyzer(json.dumps(event) + "\n")

        self.assertEqual(result.returncode, 0)
        self.assertIn("Invalid JSON lines: 0", result.stdout)
        self.assertIn("Skipped invalid events: 1", result.stdout)

    def test_mixed_timezone_formats(self):
        events = [
            self.make_event(
                "2026-10-28T20:00:00+00:00",
                "192.0.2.50",
                "/",
            ),
            self.make_event(
                "2026-10-28T20:00:01",
                "192.0.2.50",
                "/admin",
            ),
        ]
        content = "".join(json.dumps(event) + "\n" for event in events)

        result = self.run_analyzer(content)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Total valid requests: 2", result.stdout)

    def test_missing_file_returns_error_code_two(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            missing_file = Path(temp_dir) / "missing.jsonl"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(missing_file)],
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 2)
        self.assertIn("Error reading log file", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)

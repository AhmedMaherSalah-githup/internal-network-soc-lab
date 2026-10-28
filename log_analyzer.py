import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


WINDOW_MINUTES = 5
UNIQUE_PATH_THRESHOLD = 5


def parse_timestamp(value):
    """Parse ISO 8601 timestamps and normalize them to UTC."""
    if not isinstance(value, str):
        return None

    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        return timestamp.astimezone(timezone.utc)

    except ValueError:
        return None


def analyze_logs(log_file):
    events_by_ip = defaultdict(list)
    invalid_lines = 0
    skipped_events = 0

    try:
        with open(log_file, "r", encoding="utf-8") as file:
            for line in file:
                if not line.strip():
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    invalid_lines += 1
                    continue

                if not isinstance(event, dict):
                    skipped_events += 1
                    continue

                source_ip = event.get("source_ip")
                path = event.get("path")
                timestamp = parse_timestamp(event.get("timestamp"))

                if (
                    not isinstance(source_ip, str)
                    or not source_ip.strip()
                    or not isinstance(path, str)
                    or not path.startswith("/")
                    or timestamp is None
                ):
                    skipped_events += 1
                    continue

                events_by_ip[source_ip].append(
                    (timestamp, path)
                )

    except OSError as error:
        print(f"Error reading log file: {error}", file=sys.stderr)
        return 2

    print("=== SOC HTTP Log Analyzer ===")
    print(f"Time window: {WINDOW_MINUTES} minutes")
    print(f"Unique-path threshold: {UNIQUE_PATH_THRESHOLD}")
    print(f"Invalid JSON lines: {invalid_lines}")
    print(f"Skipped invalid events: {skipped_events}")

    for source_ip, events in sorted(events_by_ip.items()):
        events.sort(key=lambda event: event[0])

        print(f"\nSource IP: {source_ip}")
        print(f"Total valid requests: {len(events)}")
        print(f"Unique paths overall: {len({path for _, path in events})}")

        alert_found = False
        left = 0

        for right, (current_time, _) in enumerate(events):
            while (
                left <= right
                and current_time - events[left][0]
                > timedelta(minutes=WINDOW_MINUTES)
            ):
                left += 1

            window_paths = {
                path for _, path in events[left:right + 1]
            }

            if len(window_paths) >= UNIQUE_PATH_THRESHOLD:
                alert_found = True
                print(
                    "[ALERT] Possible endpoint reconnaissance "
                    f"within {WINDOW_MINUTES} minutes "
                    f"({len(window_paths)} unique paths)"
                )
                break

        if not alert_found:
            print("[INFO] No reconnaissance threshold reached")

    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(
            f"Usage: python3 {Path(sys.argv[0]).name} <log_file>",
            file=sys.stderr,
        )
        sys.exit(1)

    sys.exit(analyze_logs(sys.argv[1]))

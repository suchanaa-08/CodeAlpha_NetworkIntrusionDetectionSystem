
import json
from pathlib import Path

# Find the main project directory
BASE_DIR = Path(__file__).resolve().parents[1]

# Suricata log file
LOG_FILE = BASE_DIR / "logs" / "eve.json"


def read_alerts():

    if not LOG_FILE.exists():
        print("Error: eve.json file not found!")
        return

    alert_count = 0

    print("\n========== NIDS ALERT REPORT ==========\n")

    with open(LOG_FILE, "r", encoding="utf-8") as file:

        for line in file:

            try:
                event = json.loads(line)

                # Process only intrusion alerts
                if event.get("event_type") == "alert":

                    alert = event.get("alert", {})

                    alert_count += 1

                    print(f"Alert Number : {alert_count}")
                    print(f"Timestamp    : {event.get('timestamp')}")
                    print(f"Source IP    : {event.get('src_ip')}")
                    print(f"Destination  : {event.get('dest_ip')}")
                    print(f"Protocol     : {event.get('proto')}")
                    print(f"Signature    : {alert.get('signature')}")
                    print(f"Severity     : {alert.get('severity')}")
                    print("-" * 45)

            except json.JSONDecodeError:
                continue

    print(f"\nTotal Alerts Detected: {alert_count}")


if __name__ == "__main__":
    read_alerts()

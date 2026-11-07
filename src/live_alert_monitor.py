from response import handle_alert
import json
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
LOG_FILE = BASE_DIR / "logs" / "eve.json"


def monitor_alerts():

    print("\n========== LIVE NIDS MONITOR ==========")
    print("Waiting for new intrusion alerts...")
    print("Press Ctrl + C to stop.\n")

    if not LOG_FILE.exists():
        print("Error: eve.json not found!")
        return

    alert_count = 0

    try:
        # Open the log file and start from the end
        with open(LOG_FILE, "r", encoding="utf-8") as file:

            file.seek(0, 2)

            while True:

                line = file.readline()

                if not line:
                    time.sleep(0.5)
                    continue

                try:
                    event = json.loads(line)

                    if event.get("event_type") == "alert":

                        alert = event.get("alert", {})
                        
                        alert_count += 1
                        handle_alert(event)

                        print("\n[!] INTRUSION ALERT DETECTED")
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

    except KeyboardInterrupt:
        print("\nLive monitoring stopped.")
        print(f"New alerts detected: {alert_count}")


if __name__ == "__main__":
    monitor_alerts()

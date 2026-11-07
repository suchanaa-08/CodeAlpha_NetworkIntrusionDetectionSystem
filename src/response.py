
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]

RESPONSE_LOG = BASE_DIR / "logs" / "response.jsonl"


def handle_alert(event):

    alert = event.get("alert", {})

    source_ip = event.get("src_ip", "Unknown")
    destination_ip = event.get("dest_ip", "Unknown")
    protocol = event.get("proto", "Unknown")
    signature = alert.get("signature", "Unknown")
    severity = alert.get("severity", 3)

    # Determine recommended response
    if severity == 1:
        action = "URGENT INVESTIGATION REQUIRED"

    elif severity == 2:
        action = "HIGH PRIORITY INVESTIGATION"

    else:
        action = "LOGGED FOR SECURITY REVIEW"

    # Create response record
    response = {
        "timestamp": event.get("timestamp"),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "signature": signature,
        "severity": severity,
        "response_action": action
    }

    # Save response record
    with open(RESPONSE_LOG, "a", encoding="utf-8") as file:
        file.write(json.dumps(response) + "\n")

    print("\n========== INTRUSION RESPONSE ==========")
    print(f"Source IP      : {source_ip}")
    print(f"Destination IP : {destination_ip}")
    print(f"Severity       : {severity}")
    print(f"Response       : {action}")
    print("Action Status  : Recorded successfully")
    print("=" * 42)

from backend.ollama.service import explain_alert


def main():
    alert_type = "Possible Port Scan"

    evidence = """
- Source IP: 192.168.1.50
- Destination IPs contacted: 12
- Unique destination ports: 40
- Total connections: 250 in 60 seconds
- Zeek weird events: 5
- Services observed: ssh, http, dns
"""

    try:
        answer = explain_alert(alert_type, evidence)
        print("\n=== OLLAMA ANALYSIS ===\n")
        print(answer)
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
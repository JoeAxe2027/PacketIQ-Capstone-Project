import json
from collections import Counter

# Log file paths
CONN_LOG = "conn.log"
WEIRD_LOG = "weird.log"
PACKET_FILTER_LOG = "packet_filter.log"


def analyze_conn_log(file):
    total_connections = 0
    src_ips = Counter()
    dst_ips = Counter()
    services = Counter()

    with open(file, "r") as f:
        for line in f:
            try:
                record = json.loads(line)
                total_connections += 1

                src = record.get("id.orig_h")
                dst = record.get("id.resp_h")
                service = record.get("service")

                if src:
                    src_ips[src] += 1
                if dst:
                    dst_ips[dst] += 1
                if service:
                    services[service] += 1

            except json.JSONDecodeError:
                continue

    print("\n---- Connection Summary ----")
    print("Total Connections:", total_connections)

    print("\nTop Source IPs:")
    for ip, count in src_ips.most_common(10):
        print(ip, count)

    print("\nTop Destination IPs:")
    for ip, count in dst_ips.most_common(10):
        print(ip, count)

    print("\nServices Observed:")
    for svc, count in services.most_common():
        print(svc, count)


def analyze_weird_log(file):
    weird_events = Counter()

    with open(file, "r") as f:
        for line in f:
            try:
                record = json.loads(line)
                weird = record.get("name")

                if weird:
                    weird_events[weird] += 1

            except json.JSONDecodeError:
                continue

    print("\n---- Weird Events ----")
    for event, count in weird_events.most_common():
        print(event, count)


def analyze_packet_filter_log(file):
    filters = Counter()

    with open(file, "r") as f:
        for line in f:
            try:
                record = json.loads(line)
                node = record.get("node")

                if node:
                    filters[node] += 1

            except json.JSONDecodeError:
                continue

    print("\n---- Packet Filter Summary ----")
    for node, count in filters.most_common():
        print(node, count)


def main():
    analyze_conn_log(CONN_LOG)
    analyze_weird_log(WEIRD_LOG)
    analyze_packet_filter_log(PACKET_FILTER_LOG)


if __name__ == "__main__":
    main()
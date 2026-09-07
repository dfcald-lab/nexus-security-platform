#!/usr/bin/env python3

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


NEXUS = Path.home() / "nexus"

EVENT_DIR = Path(
    os.environ.get(
        "NEXUS_EVENT_DIR",
        str(
            NEXUS
            / "monitoring"
            / "events"
        ),
    )
)

EVENT_LOG = EVENT_DIR / "events.jsonl"


def load_json(path):
    path = Path(path)

    if not path.exists():
        raise SystemExit(
            f"ERROR: File not found: {path}"
        )

    try:
        with path.open("r") as file:
            return json.load(file)
    except json.JSONDecodeError as error:
        raise SystemExit(
            f"ERROR: Invalid JSON in {path}: {error}"
        )


def connected_ports(topology):
    result = {}

    for port in topology.get("ports", []):
        if not isinstance(port, dict):
            continue

        name = port.get("port")

        if not name:
            continue

        classification = port.get(
            "classification",
            "UNKNOWN",
        )

        if classification == "DISCONNECTED":
            continue

        result[name] = {
            "status": port.get(
                "status",
                "unknown",
            ),
            "vlan": port.get(
                "vlan",
                "Unknown",
            ),
            "description": port.get(
                "description",
                "",
            ),
            "classification": classification,
        }

    return result


def endpoint_map(topology):
    result = {}

    for port in topology.get("ports", []):
        if not isinstance(port, dict):
            continue

        port_name = port.get("port")

        if not port_name:
            continue

        for endpoint in port.get(
            "observed_endpoints",
            [],
        ):
            if not isinstance(endpoint, dict):
                continue

            mac = endpoint.get("mac")

            if not mac:
                continue

            result[mac.lower()] = {
                "port": port_name,
                "ip": endpoint.get(
                    "ip",
                    "Unknown",
                ),
                "device_id": endpoint.get(
                    "device_id",
                    "UNKNOWN",
                ),
                "device_type": endpoint.get(
                    "device_type",
                    "UNKNOWN",
                ),
                "hostname": endpoint.get(
                    "hostname",
                    "",
                ),
            }

    return result


def topology_events(old, new):
    events = []

    old_ports = connected_ports(old)
    new_ports = connected_ports(new)

    old_endpoints = endpoint_map(old)
    new_endpoints = endpoint_map(new)

    # --------------------------------------------------------
    # Newly active topology ports
    # --------------------------------------------------------

    for port in sorted(
        set(new_ports) - set(old_ports)
    ):
        current = new_ports[port]

        events.append(
            (
                "MEDIUM",
                10,
                (
                    "Topology port became active: "
                    f"{port} "
                    f"| Classification={current['classification']} "
                    f"| VLAN={current['vlan']}"
                ),
            )
        )

    # --------------------------------------------------------
    # Ports no longer active
    # --------------------------------------------------------

    for port in sorted(
        set(old_ports) - set(new_ports)
    ):
        previous = old_ports[port]

        events.append(
            (
                "MEDIUM",
                10,
                (
                    "Topology port became inactive: "
                    f"{port} "
                    f"| Previous classification="
                    f"{previous['classification']}"
                ),
            )
        )

    # --------------------------------------------------------
    # Classification changes
    # --------------------------------------------------------

    for port in sorted(
        set(old_ports) & set(new_ports)
    ):
        previous = old_ports[port]
        current = new_ports[port]

        if previous["classification"] != current["classification"]:
            events.append(
                (
                    "MEDIUM",
                    15,
                    (
                        "Topology classification changed: "
                        f"{port} "
                        f"{previous['classification']} -> "
                        f"{current['classification']}"
                    ),
                )
            )

        if previous["vlan"] != current["vlan"]:
            events.append(
                (
                    "HIGH",
                    20,
                    (
                        "Topology VLAN changed: "
                        f"{port} "
                        f"{previous['vlan']} -> "
                        f"{current['vlan']}"
                    ),
                )
            )

    # --------------------------------------------------------
    # Endpoint moved between ports
    # --------------------------------------------------------

    for mac in sorted(
        set(old_endpoints) & set(new_endpoints)
    ):
        previous = old_endpoints[mac]
        current = new_endpoints[mac]

        if previous["port"] != current["port"]:
            events.append(
                (
                    "HIGH",
                    25,
                    (
                        "Topology endpoint moved: "
                        f"{mac} "
                        f"{previous['port']} -> "
                        f"{current['port']} "
                        f"| Device={current['device_id']} "
                        f"| IP={current['ip']}"
                    ),
                )
            )

    # --------------------------------------------------------
    # Newly identified endpoint
    # --------------------------------------------------------

    for mac in sorted(
        set(new_endpoints) - set(old_endpoints)
    ):
        current = new_endpoints[mac]

        # Device identity is more significant than an
        # otherwise unknown raw MAC observation.
        if current["device_id"] != "UNKNOWN":
            events.append(
                (
                    "MEDIUM",
                    15,
                    (
                        "Topology endpoint identified: "
                        f"{current['device_id']} "
                        f"| MAC={mac} "
                        f"| Port={current['port']} "
                        f"| IP={current['ip']}"
                    ),
                )
            )

    return events


def persist_events(events):
    if not events:
        return

    EVENT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = datetime.now(
        timezone.utc
    ).isoformat()

    with EVENT_LOG.open("a") as file:
        for severity, score, message in events:
            record = {
                "timestamp": timestamp,
                "risk_level": severity,
                "event_score": score,
                "event_type": "topology_change",
                "severity": severity,
                "score": score,
                "message": message,
            }

            file.write(
                json.dumps(
                    record,
                    sort_keys=True,
                )
                + "\n"
            )


def main():
    if len(sys.argv) not in (3, 4):
        print(
            "Usage: python3 -m scripts.agent.topology_diff "
            "OLD.json NEW.json [--live]"
        )
        sys.exit(1)

    old_path = sys.argv[1]
    new_path = sys.argv[2]

    live_mode = (
        len(sys.argv) == 4
        and sys.argv[3] == "--live"
    )

    old = load_json(old_path)
    new = load_json(new_path)

    events = topology_events(
        old,
        new,
    )

    print()
    print(
        "===================================="
    )
    print(
        "       NEXUS TOPOLOGY DIFF"
    )
    print(
        "===================================="
    )
    print()

    print(
        f"Previous topology: {old_path}"
    )
    print(
        f"Current topology:  {new_path}"
    )
    print()

    if not events:
        print(
            "No topology changes detected."
        )
    else:
        print(
            f"Topology changes: {len(events)}"
        )
        print()

        for severity, score, message in events:
            print(
                f"[{severity:<9}] +{score:<2} {message}"
            )

    if live_mode and events:
        persist_events(events)

        print()
        print(
            f"Topology events written to: {EVENT_LOG}"
        )

    print()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3

import hashlib
import json
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from scripts.agent.event_classifier import classify_event

NEXUS = Path.home() / "nexus"

EVENT_STATE = (
    NEXUS
    / "monitoring"
    / "events"
    / "event_state.json"
)

EVENT_LOG = (
    NEXUS
    / "monitoring"
    / "events"
    / "events.jsonl"
)

INCIDENT_HISTORY = (
    NEXUS
    / "monitoring"
    / "events"
    / "incident_history.json"
)

DEVICE_HISTORY = (
    NEXUS
    / "monitoring"
    / "devices"
    / "device_history.json"
)

TOPOLOGY = (
    NEXUS
    / "monitoring"
    / "topology"
    / "current.json"
)

JETSON_USER = "jetson"
JETSON_HOST = "192.0.2.26"
SSH_KEY = Path.home() / ".ssh" / "nexus_jetson"

REMOTE_DIR = "/home/jetson/nexus/hardware"
REMOTE_FILE = f"{REMOTE_DIR}/state.json"


SEVERITY_ORDER = {
    "INFO": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}


def load_json(path, default):

    try:

        with path.open() as file:
            data = json.load(file)

        return data

    except (
        OSError,
        json.JSONDecodeError,
    ):

        return default


def parse_event(key):

    parts = key.split(
        "|",
        2,
    )

    if len(parts) != 3:
        return {
            "severity": "INFO",
            "score": 0,
            "message": key,
            "classification": "NORMAL",
        }

    severity, score, message = parts

    try:
        score = int(score)
    except ValueError:
        score = 0

    classification = classify_event(
        message,
        severity,
        score,
    )

    return {
        "severity": severity,
        "score": score,
        "message": message,
        "classification": classification,
    }

def incident_id(event):
    raw = (
        f"{event.get('severity', 'INFO')}"
        f"|{event.get('score', 0)}"
        f"|{event.get('message', '')}"
    )

    digest = hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()[:8].upper()

    return f"INC-{digest}"


def load_event_timestamps():
    timestamps = {}

    if not EVENT_LOG.exists():
        return timestamps

    try:
        with EVENT_LOG.open("r") as file:
            for line in file:
                line = line.strip()

                if not line:
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if not isinstance(event, dict):
                    continue

                timestamp = event.get(
                    "timestamp"
                )

                if not timestamp:
                    continue

                key = (
                    f"{event.get('severity', 'INFO')}"
                    f"|{event.get('score', 0)}"
                    f"|{event.get('message', '')}"
                )

                current = timestamps.get(key)

                if current is None or timestamp > current:
                    timestamps[key] = timestamp

    except OSError:
        pass

    return timestamps


def iso_now():
    return datetime.now(
        timezone.utc
    ).isoformat()


def duration_seconds(start, end):
    if not start or not end:
        return None

    try:
        started = datetime.fromisoformat(
            str(start).replace(
                "Z",
                "+00:00",
            )
        )

        finished = datetime.fromisoformat(
            str(end).replace(
                "Z",
                "+00:00",
            )
        )

        return max(
            0,
            int(
                (
                    finished - started
                ).total_seconds()
            ),
        )

    except ValueError:
        return None


def build_incident_history(
    event_state,
    event_timestamps,
):
    history = load_json(
        INCIDENT_HISTORY,
        {
            "incidents": {},
        },
    )

    incidents = history.get(
        "incidents",
        {},
    )

    if not isinstance(
        incidents,
        dict,
    ):
        incidents = {}

    active_events = event_state.get(
        "active_events",
        [],
    )

    resolved_events = event_state.get(
        "resolved_events",
        [],
    )

    if not isinstance(active_events, list):
        active_events = []

    if not isinstance(resolved_events, list):
        resolved_events = []

    now = iso_now()

    active_ids = set()

    for key in active_events:

        parsed = parse_event(key)

        identifier = incident_id(
            parsed
        )

        active_ids.add(identifier)

        record = incidents.get(
            identifier
        )

        if not isinstance(record, dict):

            record = {
                "incident_id": identifier,
                "severity": parsed["severity"],
                "score": parsed["score"],
                "message": parsed["message"],
                "detected_at": (
                    event_timestamps.get(key)
                    or now
                ),
                "last_detected_at": (
                    event_timestamps.get(key)
                    or now
                ),
                "resolved_at": None,
                "duration_seconds": None,
                "activation_count": 1,
                "state": "ACTIVE",
                "resolution_status": None,
            }

        else:

            was_resolved = (
                record.get("state")
                == "RESOLVED"
            )

            record["severity"] = parsed[
                "severity"
            ]

            record["score"] = parsed[
                "score"
            ]

            record["message"] = parsed[
                "message"
            ]

            record["last_detected_at"] = (
                event_timestamps.get(key)
                or now
            )

            if was_resolved:
                record["activation_count"] = (
                    int(
                        record.get(
                            "activation_count",
                            0,
                        )
                    )
                    + 1
                )

            record["state"] = "ACTIVE"
            record["resolved_at"] = None
            record["duration_seconds"] = None
            record["resolution_status"] = None

        incidents[identifier] = record

    for key in resolved_events:

        parsed = parse_event(key)

        identifier = incident_id(
            parsed
        )

        record = incidents.get(
            identifier
        )

        if not isinstance(record, dict):

            incidents[identifier] = {
                "incident_id": identifier,
                "severity": parsed["severity"],
                "score": parsed["score"],
                "message": parsed["message"],
                "detected_at": (
                    event_timestamps.get(key)
                ),
                "last_detected_at": (
                    event_timestamps.get(key)
                ),
                "resolved_at": None,
                "duration_seconds": None,
                "activation_count": 1,
                "state": "RESOLVED",
                "resolution_status": (
                    "HISTORICAL_UNKNOWN"
                ),
            }

            continue

        if identifier in active_ids:
            continue

        record["severity"] = parsed[
            "severity"
        ]

        record["score"] = parsed[
            "score"
        ]

        record["message"] = parsed[
            "message"
        ]

        if record.get("state") == "ACTIVE":

            record["resolved_at"] = now

            record["duration_seconds"] = (
                duration_seconds(
                    record.get(
                        "detected_at"
                    ),
                    now,
                )
            )

            record["resolution_status"] = (
                "OBSERVED"
            )

        elif not record.get(
            "resolved_at"
        ):

            record["resolution_status"] = (
                "HISTORICAL_UNKNOWN"
            )

        record["state"] = "RESOLVED"

        incidents[identifier] = record

    history["incidents"] = incidents

    with INCIDENT_HISTORY.open(
        "w"
    ) as file:

        json.dump(
            history,
            file,
            indent=2,
        )

        file.write("\n")

    return incidents


def build_state():

    event_state = load_json(
        EVENT_STATE,
        {
            "active_events": [],
            "resolved_events": [],
        },
    )

    device_data = load_json(
        DEVICE_HISTORY,
        {"devices": {}},
    )

    devices = device_data.get(
        "devices",
        {},
    )

    if not isinstance(devices, dict):
        devices = {}

    active_events = event_state.get(
        "active_events",
        [],
    )

    parsed = [
        parse_event(event)
        for event in active_events
    ]

    parsed.sort(
        key=lambda event: (
            SEVERITY_ORDER.get(
                event["severity"],
                0,
            ),
            event["score"],
        ),
        reverse=True,
    )

    actionable = [
        event
        for event in parsed
        if event.get("classification") != "NORMAL"
    ]

    if actionable:

        top = actionable[0]

        severity = top["severity"]
        event_classification = top["classification"]
        top_event = top["message"]

    else:

        severity = "INFO"
        event_classification = "NORMAL"
        top_event = "NO ALERT"

    active_count = len(
        active_events
    )

    actionable_count = len(
        actionable
    )

    if severity == "CRITICAL":
        risk = "CRITICAL"
    elif severity == "HIGH":
        risk = "HIGH"
    elif severity == "MEDIUM":
        risk = "MEDIUM"
    else:
        risk = "LOW"

    topology = load_json(
        TOPOLOGY,
        {},
    )

    nodes = topology.get(
        "nodes",
        {},
    )

    if not isinstance(nodes, dict):
        nodes = {}

    switch = topology.get(
        "switch",
        {},
    )

    gateway = topology.get(
        "default_gateway",
        {},
    )

    port_nodes = [
        node
        for node in nodes.values()
        if isinstance(node, dict)
        and node.get("type") == "SWITCH_PORT"
    ]

    classification_counts = {}

    for node in port_nodes:
        classification = node.get(
            "classification",
            "UNKNOWN",
        )

        classification_counts[classification] = (
            classification_counts.get(
                classification,
                0,
            )
            + 1
        )

    network_devices = []

    for device_id, record in devices.items():

        current = record.get(
            "current",
            {},
        )

        device_type = current.get(
            "device_type",
            "UNKNOWN",
        )

        vendor = current.get(
            "vendor",
            "Unknown",
        )

        ip = current.get(
            "ip",
            "Unknown",
        )

        port = current.get(
            "port",
            "Unknown",
        )

        vlan = current.get(
            "vlan",
            "Unknown",
        )

        # Topology may contain stronger identity information
        # than device history, especially for infrastructure
        # endpoints such as the Jetson.

        mac_normalized = (
            device_id
            .replace(".", "")
            .replace(":", "")
            .replace("-", "")
            .lower()
        )

        mac_node_id = f"mac:{mac_normalized}"

        mac_node = nodes.get(
            mac_node_id,
            {},
        )

        if isinstance(
            mac_node,
            dict,
        ):

            topology_ip = mac_node.get(
                "ip",
            )

            if topology_ip:
                ip = topology_ip

            for edge in topology.get(
                "edges",
                [],
            ):

                if not isinstance(
                    edge,
                    dict,
                ):
                    continue

                if (
                    edge.get("source")
                    != mac_node_id
                ):
                    continue

                if (
                    edge.get("type")
                    == "DEVICE_IDENTITY"
                ):

                    identity_node_id = (
                        edge.get("target")
                    )

                    identity_node = nodes.get(
                        identity_node_id,
                        {},
                    )

                    if isinstance(
                        identity_node,
                        dict,
                    ):

                        device_type = (
                            identity_node.get(
                                "device_type",
                                device_type,
                            )
                        )

                        vendor = (
                            identity_node.get(
                                "vendor",
                                vendor,
                            )
                        )

                        hostname = (
                            identity_node.get(
                                "hostname",
                            )
                        )

                        if hostname:
                            device_id = (
                                f"jetson:{hostname}"
                            )

                        os_name = (
                            identity_node.get(
                                "os",
                            )
                        )

                    break

                if (
                    edge.get("target")
                    == mac_node_id
                ) and (
                    edge.get("type")
                    == "SWITCH_PORT"
                ):

                    port_node_id = (
                        edge.get("source")
                    )

                    port_node = nodes.get(
                        port_node_id,
                        {},
                    )

                    if isinstance(
                        port_node,
                        dict,
                    ):

                        port = (
                            port_node.get(
                                "port",
                                port,
                            )
                        )

                        vlan = (
                            port_node.get(
                                "vlan",
                                vlan,
                            )
                        )

        network_devices.append(
            {
                "device_id": device_id,
                "device_type": device_type,
                "vendor": vendor,
                "ip": ip,
                "port": port,
                "vlan": vlan,
                "observations": record.get(
                    "observations",
                    0,
                ),
            }
        )

    network_devices.sort(
        key=lambda device: device["device_id"]
    )

    event_timestamps = load_event_timestamps()

    incident_history = build_incident_history(
        event_state,
        event_timestamps,
    )

    parsed_active_events = []

    for event in active_events:
        parsed = parse_event(event)
        identifier = incident_id(parsed)

        lifecycle = incident_history.get(
            identifier,
            {},
        )

        parsed["incident_id"] = identifier
        parsed["state"] = "ACTIVE"
        parsed["detected_at"] = lifecycle.get(
            "detected_at"
        )
        parsed["last_detected_at"] = lifecycle.get(
            "last_detected_at"
        )
        parsed["resolved_at"] = lifecycle.get(
            "resolved_at"
        )
        parsed["duration_seconds"] = lifecycle.get(
            "duration_seconds"
        )
        parsed["activation_count"] = lifecycle.get(
            "activation_count",
            1,
        )

        parsed_active_events.append(parsed)

    parsed_active_events.sort(
        key=lambda event: (
            SEVERITY_ORDER.get(
                event["severity"],
                0,
            ),
            event["score"],
        ),
        reverse=True,
    )

    resolved_events = event_state.get(
        "resolved_events",
        [],
    )

    if not isinstance(
        resolved_events,
        list,
    ):
        resolved_events = []

    parsed_resolved_events = []

    for index, event in enumerate(
        resolved_events
    ):
        parsed = parse_event(event)
        identifier = incident_id(parsed)

        lifecycle = incident_history.get(
            identifier,
            {},
        )

        parsed["incident_id"] = identifier
        parsed["event_id"] = index
        parsed["state"] = "RESOLVED"
        parsed["detected_at"] = lifecycle.get(
            "detected_at"
        )
        parsed["last_detected_at"] = lifecycle.get(
            "last_detected_at"
        )
        parsed["resolved_at"] = lifecycle.get(
            "resolved_at"
        )
        parsed["duration_seconds"] = lifecycle.get(
            "duration_seconds"
        )
        parsed["activation_count"] = lifecycle.get(
            "activation_count",
            1,
        )
        parsed["resolution_status"] = lifecycle.get(
            "resolution_status"
        )

        parsed_resolved_events.append(parsed)

    parsed_resolved_events.reverse()

    return {
        "status": "ONLINE",
        "risk": risk,
        "severity": severity,
        "classification": event_classification,
        "active_events": active_count,
	"actionable_events": actionable_count,
        "devices": len(devices),
        "top_event": top_event,
        "network": {
            "switch": {
                "hostname": switch.get(
                    "hostname",
                    "Unknown",
                ),
                "model": switch.get(
                    "model",
                    "Unknown",
                ),
                "management_ip": switch.get(
                    "management_ip",
                    "Unknown",
                ),
            },
            "gateway": {
                "ip": gateway.get(
                    "ip",
                    "Unknown",
                ),
            },
            "ports": {
                "total": len(port_nodes),
                "direct_devices": classification_counts.get(
                    "DIRECT_DEVICE",
                    0,
                ),
                "multi_mac": classification_counts.get(
                    "MULTI_MAC",
                    0,
                ),
                "connected_unknown": classification_counts.get(
                    "CONNECTED_UNKNOWN",
                    0,
                ),
                "disconnected": classification_counts.get(
                    "DISCONNECTED",
                    0,
                ),
            },
            "topology_edges": len(
                topology.get(
                    "edges",
                    [],
                )
            )
            if isinstance(
                topology.get(
                    "edges",
                    [],
                ),
                list,
            )
            else 0,
        },
        "network_devices": network_devices,
        "active_event_details": parsed_active_events,
        "resolved_event_details": parsed_resolved_events,
    }


def publish(state):

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        delete=False,
    ) as file:

        json.dump(
            state,
            file,
            indent=2,
        )

        file.write("\n")

        local_file = file.name

    try:

        subprocess.run(
            [
                "ssh",
                "-i",
                str(SSH_KEY),
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                f"{JETSON_USER}@{JETSON_HOST}",
                f"mkdir -p {REMOTE_DIR}",
            ],
            check=True,
        )

        subprocess.run(
            [
                "scp",
                "-i",
                str(SSH_KEY),
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                local_file,
                f"{JETSON_USER}@{JETSON_HOST}:{REMOTE_FILE}",
            ],
            check=True,
        )

    finally:

        Path(local_file).unlink(
            missing_ok=True
        )


def main():

    state = build_state()

    publish(state)

    print(
        "NEXUS → Jetson:"
    )

    print(
        json.dumps(
            state,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

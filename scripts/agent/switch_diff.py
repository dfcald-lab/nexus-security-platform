#!/usr/bin/env python3

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from scripts.agent.event_classifier import classify_event


# ============================================================
# NEXUS SWITCH CHANGE DETECTOR
# ============================================================

EVENT_DIR = (
    Path.home()
    / "nexus"
    / "monitoring"
    / "events"
)

EVENT_LOG = EVENT_DIR / "events.jsonl"
EVENT_STATE = EVENT_DIR / "event_state.json"

DEVICE_HISTORY_FILE = (
    Path.home()
    / "nexus"
    / "monitoring"
    / "devices"
    / "device_history.json"
)


# ============================================================
# SNAPSHOT LOADING
# ============================================================

def load_snapshot(path):

    snapshot_path = Path(path)

    if not snapshot_path.exists():
        sys.exit(
            f"ERROR: Snapshot not found: {path}"
        )

    try:
        with snapshot_path.open("r") as file:
            return json.load(file)

    except json.JSONDecodeError as error:
        sys.exit(
            f"ERROR: Invalid JSON in {path}: {error}"
        )

# ============================================================
# DEVICE HISTORY
# ============================================================

def load_device_history():

    if not DEVICE_HISTORY_FILE.exists():
        return {
            "devices": {}
        }

    try:

        with DEVICE_HISTORY_FILE.open("r") as file:
            data = json.load(file)

        if not isinstance(data, dict):
            return {
                "devices": {}
            }

        if not isinstance(
            data.get("devices"),
            dict,
        ):
            data["devices"] = {}

        return data

    except (
        json.JSONDecodeError,
        OSError,
    ):

        return {
            "devices": {}
        }


def get_device_context(
    history,
    device_id,
    device,
):

    record = history.get(
        "devices",
        {},
    ).get(
        device_id,
        {},
    )

    current = record.get(
        "current",
        {},
    )

    historical = record.get(
        "history",
        {},
    )

    previous_ports = historical.get(
        "previous_ports",
        [],
    )

    return {
        "device_id": device_id,
        "device_type": device.get(
            "device_type",
            current.get(
                "device_type",
                "UNKNOWN",
            ),
        ),
        "vendor": device.get(
            "vendor",
            current.get(
                "vendor",
                "Unknown",
            ),
        ),
        "ip": device.get(
            "ip",
            current.get(
                "ip",
                "Unknown",
            ),
        ),
        "port": device.get(
            "port",
            current.get(
                "port",
                "Unknown",
            ),
        ),
        "observations": record.get(
            "observations",
            0,
        ),
        "first_seen": record.get(
            "first_seen",
            "Unknown",
        ),
        "previous_ports": previous_ports,
    }

# ============================================================
# NORMALIZATION
# ============================================================

def normalize_snapshot(snapshot):
    """
    Remove volatile telemetry that should not trigger
    network-state change alerts.
    """

    normalized = json.loads(
        json.dumps(snapshot)
    )

    # ARP age changes continuously.
    for entry in normalized.get("arp", []):

        if isinstance(entry, dict):
            entry.pop("age", None)

    # Switch uptime changes continuously.
    if isinstance(
        normalized.get("switch"),
        dict,
    ):

        normalized["switch"].pop(
            "uptime",
            None,
        )

    return normalized


# ============================================================
# MAC / PORT INTELLIGENCE
# ============================================================

def detect_mac_port_churn(old, new):

    events = []

    old_mac_table = old.get(
        "mac_table",
        {},
    )

    new_mac_table = new.get(
        "mac_table",
        {},
    )

    if not isinstance(old_mac_table, dict):
        return events

    if not isinstance(new_mac_table, dict):
        return events

    for port in sorted(
        set(old_mac_table)
        | set(new_mac_table)
    ):

        old_macs = set(
            old_mac_table.get(
                port,
                [],
            )
        )

        new_macs = set(
            new_mac_table.get(
                port,
                [],
            )
        )

        removed = old_macs - new_macs
        added = new_macs - old_macs
        common = old_macs & new_macs

        if (
            len(removed) == 1
            and len(added) == 1
            and len(common) >= 1
        ):

            events.append(
                {
                    "port": port,
                    "old_mac": next(
                        iter(removed)
                    ),
                    "new_mac": next(
                        iter(added)
                    ),
                }
            )

    return events

# ============================================================
# DEVICE-AWARE MAC CHANGES
# ============================================================

def is_known_device_port(
    snapshot,
    port,
):

    devices = snapshot.get(
        "devices",
        {},
    )

    if not isinstance(
        devices,
        dict,
    ):
        return False

    # Device IDs represent device identity.
    # The physical switch port is stored inside
    # each device record under "port".
    for device in devices.values():

        if not isinstance(
            device,
            dict,
        ):
            continue

        if device.get("port") == port:
            return True

    return False

def is_known_device_mac_change(
    old_snapshot,
    new_snapshot,
    path,
):

    if not path.startswith(
        "mac_table."
    ):
        return False

    port = path.split(
        ".",
        1,
    )[1]

    return (
        is_known_device_port(
            old_snapshot,
            port,
        )
        or
        is_known_device_port(
            new_snapshot,
            port,
        )
    )

# ============================================================
# COMPARISON
# ============================================================

def compare_values(
    old,
    new,
    path="",
):

    changes = []

    if (
        isinstance(old, dict)
        and isinstance(new, dict)
    ):

        old_keys = set(old.keys())
        new_keys = set(new.keys())

        for key in sorted(
            new_keys - old_keys
        ):

            changes.append(
                (
                    "ADDED",
                    (
                        f"{path}.{key}"
                        if path
                        else key
                    ),
                    None,
                    new[key],
                )
            )

        for key in sorted(
            old_keys - new_keys
        ):

            changes.append(
                (
                    "REMOVED",
                    (
                        f"{path}.{key}"
                        if path
                        else key
                    ),
                    old[key],
                    None,
                )
            )

        for key in sorted(
            old_keys & new_keys
        ):

            child_path = (
                f"{path}.{key}"
                if path
                else key
            )

            changes.extend(
                compare_values(
                    old[key],
                    new[key],
                    child_path,
                )
            )

        return changes

    if (
        isinstance(old, list)
        and isinstance(new, list)
    ):

        if old != new:

            changes.append(
                (
                    "CHANGED",
                    path,
                    old,
                    new,
                )
            )

        return changes

    if old != new:

        changes.append(
            (
                "CHANGED",
                path,
                old,
                new,
            )
        )

    return changes


# ============================================================
# VALUE FORMATTING
# ============================================================

def format_value(value):

    if isinstance(
        value,
        (
            dict,
            list,
        ),
    ):

        return json.dumps(
            value,
            sort_keys=True,
        )

    return str(value)


# ============================================================
# OUTPUT
# ============================================================

def print_section(title):

    print()

    print(
        f"============ {title} ============"
    )


# ============================================================
# EVENT ANALYSIS
# ============================================================

def analyze_network_events(
    old_snapshot,
    new_snapshot,
    changes,
):

    events = []

    churn_events = detect_mac_port_churn(
        old_snapshot,
        new_snapshot,
    )

    churn_removed = set()
    churn_added = set()

    for churn in churn_events:

        churn_removed.add(
            churn["old_mac"]
        )

        churn_added.add(
            churn["new_mac"]
        )

        events.append(
            (
                "MEDIUM",
                10,
                (
                    "MAC identity changed on "
                    f"{churn['port']}: "
                    f"{churn['old_mac']} -> "
                    f"{churn['new_mac']}"
                ),
            )
        )

    for change in changes:

        change_type, path, old_value, new_value = change

        # ----------------------------------------------------
        # DEVICE IDENTITY ADDITIONS / REMOVALS
        #
        # Device IDs are MAC-based. Therefore an added or
        # removed device entry represents a real logical
        # device identity change.
        # ----------------------------------------------------

        if (
            change_type == "ADDED"
            and path.startswith("devices.")
        ):

            device_id = path[
                len("devices.") :
            ]

            events.append(
                (
                    "MEDIUM",
                    15,
                    (
                        "Device discovered: "
                        f"{device_id}"
                    ),
                )
            )

            continue

        if (
            change_type == "REMOVED"
            and path.startswith("devices.")
        ):

            device_id = path[
                len("devices.") :
            ]

            events.append(
                (
                    "MEDIUM",
                    15,
                    (
                        "Device removed: "
                        f"{device_id}"
                    ),
                )
            )

            continue

        # ----------------------------------------------------
        # DEVICE MAC INVENTORY CHANGES
        # ----------------------------------------------------

        if (
            change_type == "CHANGED"
            and path.startswith("devices.")
            and ".mac_addresses" in path
        ):

            device_path, _ = path.rsplit(
                ".mac_addresses",
                1,
            )

            device_id = device_path[
                len("devices.") :
            ]

            old_macs = set(
                old_value
                if isinstance(old_value, list)
                else []
            )

            new_macs = set(
                new_value
                if isinstance(new_value, list)
                else []
            )

            removed_macs = sorted(
                old_macs - new_macs
            )

            added_macs = sorted(
                new_macs - old_macs
            )

            if (
                len(removed_macs) == 1
                and len(added_macs) == 1
            ):

                events.append(
                    (
                        "MEDIUM",
                        10,
                        (
                            "MAC identity changed on "
                            f"{device_id}: "
                            f"{removed_macs[0]} -> "
                            f"{added_macs[0]}"
                        ),
                    )
                )

            else:

                for mac in removed_macs:

                    events.append(
                        (
                            "MEDIUM",
                            10,
                            (
                                "MAC removed from device "
                                f"{device_id}: {mac}"
                            ),
                        )
                    )

                for mac in added_macs:

                    events.append(
                        (
                            "MEDIUM",
                            15,
                            (
                                "MAC added to device "
                                f"{device_id}: {mac}"
                            ),
                        )
                    )

            continue

        # ----------------------------------------------------
        # DEVICE LOCATION CHANGES
        # ----------------------------------------------------

        if (
            change_type == "CHANGED"
            and path.startswith("devices.")
            and path.endswith(".port")
        ):

            device_path = path[
                len("devices.") :
            ]

            device_id = device_path[
                :-len(".port")
            ]

            device = (
                new_snapshot
                .get("devices", {})
                .get(device_id, {})
            )

            history = load_device_history()

            context = get_device_context(
                history,
                device_id,
                device,
            )

            events.append(
                (
                    "HIGH",
                    25,
                    (
                        "Device moved: "
                        f"{device_id} "
                        f"{old_value} -> "
                        f"{new_value} "
                        f"| Type={context['device_type']} "
                        f"| Vendor={context['vendor']} "
                        f"| IP={context['ip']} "
                        f"| Observations={context['observations']}"
                    ),
                )
            )

            continue

        # ----------------------------------------------------
        # OTHER DEVICE CHANGES
        # ----------------------------------------------------

        if path.startswith(
            "devices."
        ):

            if change_type == "CHANGED":

                events.append(
                    (
                        "INFO",
                        0,
                        (
                            "Device state changed: "
                            f"{path}"
                        ),
                    )
                )

            continue

        # ----------------------------------------------------
        # MAC TABLE CHANGES
        # ----------------------------------------------------

        if path.startswith(
            "mac_table."
        ):

            if is_known_device_mac_change(
                old_snapshot,
                new_snapshot,
                path,
            ):
                continue

            events.append(
                (
                    "INFO",
                    0,
                    (
                        "MAC table changed: "
                        f"{path}"
                    ),
                )
            )

            continue

        # ----------------------------------------------------
        # HEALTH CHANGES
        # ----------------------------------------------------

        if path.startswith(
            "health."
        ):

            events.append(
                (
                    "INFO",
                    0,
                    (
                        "Network health metric changed: "
                        f"{path}"
                    ),
                )
            )

            continue

        # ----------------------------------------------------
        # PORT MAC COUNT CHANGES
        # ----------------------------------------------------

        if path.endswith(
            ".mac_count"
        ):

            port = path.rsplit(
                ".",
                1,
            )[0]

            if is_known_device_port(
                new_snapshot,
                port,
            ):
                continue

            events.append(
                (
                    "INFO",
                    0,
                    (
                        "MAC count changed on port: "
                        f"{port}"
                    ),
                )
            )

            continue

    return events

# ============================================================
# EVENT STATE
# ============================================================

def load_event_state():

    if not EVENT_STATE.exists():
        return {
            "active_events": []
        }

    try:

        with EVENT_STATE.open("r") as file:
            state = json.load(file)

        if not isinstance(state, dict):
            return {
                "active_events": []
            }

        if not isinstance(
            state.get("active_events"),
            list,
        ):
            state["active_events"] = []

        return state

    except (
        json.JSONDecodeError,
        OSError,
    ):

        return {
            "active_events": []
        }

def save_event_state(state):

    EVENT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    with EVENT_STATE.open("w") as file:

        json.dump(
            state,
            file,
            indent=2,
        )


def event_key(
    severity,
    score,
    message,
):

    return (
        f"{severity}|"
        f"{score}|"
        f"{message}"
    )


def filter_new_events(events):

    state = load_event_state()

    active_events = set(
        state.get(
            "active_events",
            [],
        )
    )

    new_events = []
    seen_this_run = set()

    for severity, score, message in events:

        key = event_key(
            severity,
            score,
            message,
        )

        # Already active from a previous monitoring cycle.
        if key in active_events:
            continue

        # Already detected earlier in this same run.
        if key in seen_this_run:
            continue

        seen_this_run.add(key)

        new_events.append(
            (
                severity,
                score,
                message,
            )
        )

    return new_events

def update_event_state(events):

    state = load_event_state()

    active_events = set()

    for severity, score, message in events:

        active_events.add(
            event_key(
                severity,
                score,
                message,
            )
        )

    state["active_events"] = sorted(
        active_events
    )

    save_event_state(
        state
    )

# ============================================================
# EVENT PERSISTENCE
# ============================================================

def save_events(
    events,
    event_score,
    risk_level,
    old_path,
    new_path,
):

    if not events:
        return None

    EVENT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = datetime.now(
        timezone.utc
    )

    with EVENT_LOG.open(
        "a"
    ) as file:

        for severity, score, message in events:

            classification = classify_event(
                message,
                severity,
                score,
            )

            event_record = {
                "timestamp": timestamp.isoformat(),
                "risk_level": risk_level,
                "event_score": event_score,
                "event_type": "network_change",
                "classification": classification,
                "severity": severity,
                "score": score,
                "message": message,
                "previous_snapshot": str(
                    old_path
                ),
                "current_snapshot": str(
                    new_path
                ),
            }

            file.write(
                json.dumps(
                    event_record,
                    sort_keys=True,
                )
                + "\n"
            )

    return EVENT_LOG


# ============================================================
# MAIN
# ============================================================

def main():

    if len(sys.argv) not in (3, 4):

        print(
            "Usage:"
        )

        print(
            "  python3 -m scripts.agent.switch_diff "
            "OLD.json NEW.json [--live]"
        )

        sys.exit(1)

    old_path = sys.argv[1]
    new_path = sys.argv[2]

    live_mode = (
        len(sys.argv) == 4
        and sys.argv[3] == "--live"
    )

    old_snapshot = load_snapshot(
        old_path
    )

    new_snapshot = load_snapshot(
        new_path
    )

    old_snapshot = normalize_snapshot(
        old_snapshot
    )

    new_snapshot = normalize_snapshot(
        new_snapshot
    )

    changes = compare_values(
        old_snapshot,
        new_snapshot,
    )

    all_events = analyze_network_events(
        old_snapshot,
        new_snapshot,
        changes,
    )

    if live_mode:
        events = filter_new_events(
            all_events
        )
    else:
        events = all_events

    print()

    print(
        "===================================="
    )

    print(
        "       NEXUS CHANGE DETECTION"
    )

    print(
        "===================================="
    )

    print()

    print(
        f"Previous snapshot: {old_path}"
    )

    print(
        f"Current snapshot:  {new_path}"
    )

    if not changes:

        print()

        print(
            "No changes detected."
        )

        print()

        print(
            "Network state is unchanged."
        )

        print()

        print(
            "===================================="
        )

        return

    added = [
        change
        for change in changes
        if change[0] == "ADDED"
    ]

    removed = [
        change
        for change in changes
        if change[0] == "REMOVED"
    ]

    changed = [
        change
        for change in changes
        if change[0] == "CHANGED"
    ]

    print_section(
        "CHANGE SUMMARY"
    )

    print(
        f"Total changes: {len(changes)}"
    )

    print(
        f"Added:         {len(added)}"
    )

    print(
        f"Removed:       {len(removed)}"
    )

    print(
        f"Changed:       {len(changed)}"
    )

    severity_order = [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
    ]

    severity_counts = {
        severity: 0
        for severity in severity_order
    }

    raw_score = 0

    for severity, score, _ in all_events:

        severity_counts[severity] += 1
        raw_score += score

    event_score = min(
        100,
        raw_score,
    )

    if event_score >= 75:

        risk_level = "CRITICAL"

    elif event_score >= 50:

        risk_level = "HIGH"

    elif event_score >= 25:

        risk_level = "MEDIUM"

    elif event_score > 0:

        risk_level = "LOW"

    else:

        risk_level = "MINIMAL"

    print()

    print(
        f"Critical:      "
        f"{severity_counts['CRITICAL']}"
    )

    print(
        f"High:          "
        f"{severity_counts['HIGH']}"
    )

    print(
        f"Medium:        "
        f"{severity_counts['MEDIUM']}"
    )

    print(
        f"Low:           "
        f"{severity_counts['LOW']}"
    )

    print(
        f"Info:           "
        f"{severity_counts['INFO']}"
    )

    print_section(
        "NETWORK EVENT SCORE"
    )

    print(
        f"Raw score:      {raw_score}"
    )

    print(
        f"Event score:    {event_score}/100"
    )

    print(
        f"Risk level:     {risk_level}"
    )

    if events:

        print_section(
            "NEW NETWORK EVENTS"
            if live_mode
            else "NETWORK EVENTS"
        )

        for severity, score, message in events:

            print(
                f"  [{severity:<9}] "
                f"+{score:<2} "
                f"{message}"
            )

    elif all_events:

        print_section(
            "NETWORK EVENTS"
        )

        print(
            "Previously recorded events detected."
        )

        print(
            "No duplicate events logged."
        )

    if added:

        print_section(
            "ADDED"
        )

        for _, path, _, new_value in added:

            print(
                f"  [+] {path}"
            )

            print(
                f"      {format_value(new_value)}"
            )

    if removed:

        print_section(
            "REMOVED"
        )

        for _, path, old_value, _ in removed:

            print(
                f"  [-] {path}"
            )

            print(
                f"      {format_value(old_value)}"
            )

    if changed:

        print_section(
            "CHANGED"
        )

        for _, path, old_value, new_value in changed:

            print(
                f"  [~] {path}"
            )

            print(
                f"      OLD: {format_value(old_value)}"
            )

            print(
                f"      NEW: {format_value(new_value)}"
            )

    # --------------------------------------------------------
    # Persist events ONLY during a live monitoring run.
    # --------------------------------------------------------

    if live_mode and events:

        event_path = save_events(
            events,
            event_score,
            risk_level,
            old_path,
            new_path,
        )

        if event_path:

            print()

            print(
                f"Event log saved: {event_path}"
            )

    elif not live_mode and events:

        print()

        print(
            "Test comparison only."
        )

        print(
            "Events were NOT written to event state."
        )

        print(
            "Use --live to persist events."
        )

    print()

    print(
        "===================================="
    )


if __name__ == "__main__":
    main()

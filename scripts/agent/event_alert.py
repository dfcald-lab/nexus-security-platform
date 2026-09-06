#!/usr/bin/env python3

import json
from pathlib import Path


# ============================================================
# NEXUS EVENT ALERT ENGINE
# ============================================================

NEXUS = Path.home() / "nexus"

EVENT_DIR = (
    NEXUS
    / "monitoring"
    / "events"
)

STATE_FILE = EVENT_DIR / "event_state.json"

ALERT_LOG = EVENT_DIR / "alerts.jsonl"

ALERT_STATE_FILE = EVENT_DIR / "alert_state.json"


# ============================================================
# LOAD JSON FILE
# ============================================================

def load_json(path, default):

    if not path.exists():
        return default

    try:

        with path.open("r") as file:
            data = json.load(file)

    except (
        json.JSONDecodeError,
        OSError,
    ):

        return default

    return data


# ============================================================
# SAVE JSON FILE
# ============================================================

def save_json(path, data):

    EVENT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open("w") as file:

        json.dump(
            data,
            file,
            indent=2,
        )


# ============================================================
# LOAD EVENT STATE
# ============================================================

def load_event_state():

    return load_json(
        STATE_FILE,
        {
            "active_events": [],
            "resolved_events": [],
        },
    )


# ============================================================
# LOAD ALERT STATE
# ============================================================

def load_alert_state():

    state = load_json(
        ALERT_STATE_FILE,
        {
            "alerted_events": [],
        },
    )

    if not isinstance(state, dict):

        state = {
            "alerted_events": [],
        }

    state.setdefault(
        "alerted_events",
        [],
    )

    return state


# ============================================================
# PARSE EVENT KEY
# ============================================================

def parse_event_key(key):

    parts = key.split(
        "|",
        2,
    )

    if len(parts) != 3:
        return None

    severity, score, message = parts

    try:

        score = int(score)

    except ValueError:

        score = 0

    return {
        "key": key,
        "severity": severity,
        "score": score,
        "message": message,
    }


# ============================================================
# ACTIONABLE EVENT
# ============================================================

def is_actionable(event):

    return event.get(
        "severity",
        "INFO",
    ) in {
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }


# ============================================================
# WRITE ALERT
# ============================================================

def write_alert(
    alert_type,
    event,
):

    EVENT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    record = {
        "alert_type": alert_type,
        "severity": event["severity"],
        "score": event["score"],
        "message": event["message"],
    }

    with ALERT_LOG.open(
        "a"
    ) as file:

        json.dump(
            record,
            file,
        )

        file.write("\n")


# ============================================================
# PROCESS ACTIVE EVENTS
# ============================================================

def process_active_events(
    state,
    alert_state,
):

    active_events = state.get(
        "active_events",
        [],
    )

    resolved_events = state.get(
        "resolved_events",
        [],
    )

    alerted_events = set(
        alert_state.get(
            "alerted_events",
            [],
        )
    )

    active_keys = set(
        active_events
    )

    resolved_keys = set(
        resolved_events
    )

    # --------------------------------------------------------
    # Remove resolved events from the alert tracking set.
    #
    # This allows an event to generate a fresh alert if it
    # disappears, resolves, and later returns.
    # --------------------------------------------------------

    alerted_events.intersection_update(
        active_keys
    )

    # --------------------------------------------------------
    # Find actionable active events.
    # --------------------------------------------------------

    new_alerts = []

    current_actionable = set()

    for key in active_events:

        event = parse_event_key(key)

        if event is None:
            continue

        if not is_actionable(event):
            continue

        current_actionable.add(key)

        if key in alerted_events:
            continue

        new_alerts.append(
            event
        )

    # --------------------------------------------------------
    # Mark newly alerted events.
    # --------------------------------------------------------

    for event in new_alerts:

        alerted_events.add(
            event["key"]
        )

    alert_state["alerted_events"] = sorted(
        alerted_events
    )

    return new_alerts


# ============================================================
# DISPLAY
# ============================================================

def display_alerts(alerts):

    print()

    print(
        "===================================="
    )

    print(
        "       NEXUS EVENT ALERTS"
    )

    print(
        "===================================="
    )

    print()

    if not alerts:

        print(
            "No new actionable alerts."
        )

        print()

        return

    for event in alerts:

        print(
            f"[{event['severity']:<9}] "
            f"+{event['score']:<2} "
            f"{event['message']}"
        )

    print()


# ============================================================
# MAIN
# ============================================================

def main():

    state = load_event_state()

    alert_state = load_alert_state()

    alerts = process_active_events(
        state,
        alert_state,
    )

    for event in alerts:

        write_alert(
            "active_event",
            event,
        )

    save_json(
        ALERT_STATE_FILE,
        alert_state,
    )

    display_alerts(
        alerts
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()

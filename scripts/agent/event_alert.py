#!/usr/bin/env python3

import json
import os
from pathlib import Path

from scripts.agent.publish_jetson_state import (
    incident_id,
    parse_event,
    is_thermal_event,
    thermal_sensor,
)


# ============================================================
# NEXUS EVENT ALERT ENGINE
# ============================================================

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

    if not isinstance(active_events, list):
        active_events = []

    if not isinstance(resolved_events, list):
        resolved_events = []

    previous_alerted = alert_state.get(
        "alerted_events",
        [],
    )

    if not isinstance(previous_alerted, list):
        previous_alerted = []

    # --------------------------------------------------------
    # Alert tracking now uses canonical incident IDs instead
    # of raw event keys.
    #
    # This means:
    #
    #   GPU thermal event ─┐
    #                      ├──> INC-XXXXXXXX
    #   TJ thermal event ──┘
    #
    # produces one alert.
    #
    # Existing raw keys are converted automatically so the
    # change does not require deleting alert_state.json.
    # --------------------------------------------------------

    alerted_incidents = set()

    for value in previous_alerted:

        if not isinstance(value, str):
            continue

        if value.startswith("INC-"):
            alerted_incidents.add(value)
            continue

        event = parse_event_key(value)

        if event is None:
            continue

        if is_actionable(event):
            alerted_incidents.add(
                incident_id(event)
            )

    # --------------------------------------------------------
    # Resolved incidents are removed from alert tracking.
    # This allows a future re-occurrence to alert again.
    # --------------------------------------------------------

    resolved_incidents = set()

    for key in resolved_events:

        event = parse_event_key(key)

        if event is None:
            continue

        resolved_incidents.add(
            incident_id(event)
        )

    alerted_incidents.difference_update(
        resolved_incidents
    )

    # --------------------------------------------------------
    # Group active actionable events by canonical incident ID.
    # --------------------------------------------------------

    groups = {}

    for key in active_events:

        event = parse_event_key(key)

        if event is None:
            continue

        if not is_actionable(event):
            continue

        identifier = incident_id(event)

        groups.setdefault(
            identifier,
            [],
        ).append(event)

    # --------------------------------------------------------
    # Build exactly one alert per incident.
    # --------------------------------------------------------

    new_alerts = []

    for identifier, group in groups.items():

        primary = max(
            group,
            key=lambda event: (
                {
                    "INFO": 0,
                    "MEDIUM": 1,
                    "HIGH": 2,
                    "CRITICAL": 3,
                }.get(
                    event.get(
                        "severity",
                        "INFO",
                    ),
                    0,
                ),
                event.get(
                    "score",
                    0,
                ),
            ),
        )

        alert = dict(primary)

        alert["incident_id"] = identifier

        # ----------------------------------------------------
        # Thermal incidents become one human-readable alert
        # while preserving the individual sensor evidence.
        # ----------------------------------------------------

        thermal_events = [
            event
            for event in group
            if is_thermal_event(event)
        ]

        if thermal_events:

            sensors = sorted(
                {
                    thermal_sensor(event)
                    for event in thermal_events
                }
            )

            alert["message"] = (
                "Thermal incident affecting: "
                + ", ".join(sensors)
            )

            alert["contributors"] = [
                {
                    "sensor": thermal_sensor(event),
                    "severity": event.get(
                        "severity",
                        "INFO",
                    ),
                    "score": event.get(
                        "score",
                        0,
                    ),
                    "message": event.get(
                        "message",
                        "",
                    ),
                }
                for event in sorted(
                    thermal_events,
                    key=lambda event:
                        thermal_sensor(event),
                )
            ]

        if identifier in alerted_incidents:
            continue

        new_alerts.append(
            alert
        )

        alerted_incidents.add(
            identifier
        )

    alert_state["alerted_events"] = sorted(
        alerted_incidents
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

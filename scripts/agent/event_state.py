#!/usr/bin/env python3

import json
import sys
from pathlib import Path


# ============================================================
# NEXUS EVENT STATE
# ============================================================

EVENT_DIR = (
    Path.home()
    / "nexus"
    / "monitoring"
    / "events"
)

EVENT_LOG = EVENT_DIR / "events.jsonl"
STATE_FILE = EVENT_DIR / "event_state.json"


# ============================================================
# LOAD EVENTS
# ============================================================

def load_events():

    if not EVENT_LOG.exists():
        return []

    events = []

    with EVENT_LOG.open("r") as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)

            except json.JSONDecodeError:
                continue

            if isinstance(event, dict):
                events.append(event)

    return events


# ============================================================
# EVENT KEY
# ============================================================

def event_key(event):

    return (
        f"{event.get('severity', 'INFO')}"
        f"|{event.get('score', 0)}"
        f"|{event.get('message', '')}"
    )


# ============================================================
# LOAD STATE
# ============================================================

def load_state():

    if not STATE_FILE.exists():

        return {
            "active_events": [],
            "resolved_events": [],
            "last_timestamp": None,
        }

    try:

        with STATE_FILE.open("r") as file:
            state = json.load(file)

    except (
        json.JSONDecodeError,
        OSError,
    ):

        return {
            "active_events": [],
            "resolved_events": [],
            "last_timestamp": None,
        }

    if not isinstance(state, dict):

        return {
            "active_events": [],
            "resolved_events": [],
            "last_timestamp": None,
        }

    state.setdefault(
        "active_events",
        [],
    )

    state.setdefault(
        "resolved_events",
        [],
    )

    state.setdefault(
        "last_timestamp",
        None,
    )

    return state


# ============================================================
# SAVE STATE
# ============================================================

def save_state(state):

    EVENT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    with STATE_FILE.open("w") as file:

        json.dump(
            state,
            file,
            indent=2,
        )


# ============================================================
# GET EVENTS FROM CURRENT MONITOR RUN
# ============================================================

def get_current_events(events, state):

    last_timestamp = state.get(
        "last_timestamp"
    )

    if not last_timestamp:
        return events

    current_events = []

    for event in events:

        timestamp = event.get(
            "timestamp"
        )

        if not timestamp:
            continue

        if timestamp > last_timestamp:

            current_events.append(
                event
            )

    return current_events


# ============================================================
# EVENT MESSAGE HELPERS
# ============================================================

def parse_key(key):

    parts = key.split(
        "|",
        2,
    )

    if len(parts) != 3:
        return (
            "INFO",
            0,
            key,
        )

    severity, score, message = parts

    try:
        score = int(score)

    except ValueError:
        score = 0

    return (
        severity,
        score,
        message,
    )


def message_from_key(key):

    return parse_key(key)[2]


# ============================================================
# TRANSIENT EVENT CLASSIFICATION
# ============================================================

TRANSIENT_EVENT_PREFIXES = (
    "MAC identity changed on ",
    "MAC removed from device ",
    "MAC added to device ",
    "MAC count changed on port: ",
    "Network health metric changed: ",
    "Device state changed: ",
    "MAC table changed: ",
)


def is_transient_event(key):

    message = message_from_key(key)

    return message.startswith(
        TRANSIENT_EVENT_PREFIXES
    )


# ============================================================
# RECONCILE EVENT STATE
# ============================================================

def reconcile(events, state):

    active_keys = set(
        state.get(
            "active_events",
            [],
        )
    )

    resolved_keys = set(
        state.get(
            "resolved_events",
            [],
        )
    )

    # --------------------------------------------------------
    # No new events were generated during this monitor run.
    #
    # Nexus is change/event based. An event that was active
    # during the previous monitoring cycle is no longer active
    # when it does not appear in the current cycle.
    # --------------------------------------------------------

    if not events:

        resolved_now = set(active_keys)

        next_resolved = set(resolved_keys)
        next_resolved.update(resolved_now)

        state["active_events"] = []
        state["resolved_events"] = sorted(next_resolved)

        return (
            set(),
            set(),
            resolved_now,
        )

    current_keys = {
        event_key(event)
        for event in events
    }

    # --------------------------------------------------------
    # Events never seen before.
    # --------------------------------------------------------

    new_events = (
        current_keys
        - active_keys
        - resolved_keys
    )

    # --------------------------------------------------------
    # Events that were previously resolved but have now
    # appeared again.
    # --------------------------------------------------------

    returned_events = (
        current_keys
        & resolved_keys
    )

    # --------------------------------------------------------
    # Explicit resolution.
    #
    # A disappearance resolves the corresponding
    # "New network device detected" event.
    # --------------------------------------------------------

    resolved_now = set()

    # --------------------------------------------------------
    # Transient change events are active only for the
    # monitoring cycle in which they are observed.
    #
    # If a transient event disappears from the current cycle,
    # resolve it automatically. Persistent conditions are
    # handled separately by the explicit resolution rules.
    # --------------------------------------------------------

    for key in active_keys:

        if (
            key not in current_keys
            and is_transient_event(key)
        ):

            resolved_now.add(key)

    for key in active_keys:

        severity, score, message = parse_key(
            key
        )

        if (
            severity == "MEDIUM"
            and message.startswith(
                "New network device detected:"
            )
        ):

            mac = message.split(
                ":",
                1,
            )[1].strip()

            disappearance_message = (
                "Network device disappeared: "
                f"{mac}"
            )

            disappearance_key = (
                "MEDIUM|10|"
                f"{disappearance_message}"
            )

            if disappearance_key in current_keys:

                resolved_now.add(
                    key
                )

    # --------------------------------------------------------
    # A MAC identity change means the previous device on
    # that port is no longer the active identity.
    #
    # Example:
    #
    # 9ca2.f4b7.2553 -> 3638.8765.ef1a
    #
    # Resolve the old "New network device detected" event
    # if it exists.
    # --------------------------------------------------------

    for key in active_keys:

        severity, score, message = parse_key(
            key
        )

        if (
            severity == "MEDIUM"
            and message.startswith(
                "New network device detected:"
            )
        ):

            old_mac = message.split(
                ":",
                1,
            )[1].strip()

            for event in events:

                current_message = event.get(
                    "message",
                    "",
                )

                if not current_message.startswith(
                    "MAC identity changed on "
                ):
                    continue

                transition = current_message.split(
                    ":",
                    1,
                )

                if len(transition) != 2:
                    continue

                mac_change = transition[1].strip()

                if " -> " not in mac_change:
                    continue

                changed_old_mac, _ = mac_change.split(
                    " -> ",
                    1,
                )

                if changed_old_mac.strip() == old_mac:

                    resolved_now.add(
                        key
                    )

    # --------------------------------------------------------
    # Build next active state.
    # --------------------------------------------------------

    next_active = set(
        active_keys
    )

    # Newly observed events become active.
    next_active.update(
        new_events
    )

    # Previously resolved events that returned become active.
    next_active.update(
        returned_events
    )

    # Explicitly resolved events leave active state.
    next_active.difference_update(
        resolved_now
    )

    # --------------------------------------------------------
    # Build resolved history.
    # --------------------------------------------------------

    next_resolved = set(
        resolved_keys
    )

    next_resolved.update(
        resolved_now
    )

    # A returned event is active again.
    next_resolved.difference_update(
        returned_events
    )

    # --------------------------------------------------------
    # Save state.
    # --------------------------------------------------------

    state["active_events"] = sorted(
        next_active
    )

    state["resolved_events"] = sorted(
        next_resolved
    )

    # --------------------------------------------------------
    # Update timestamp.
    # --------------------------------------------------------

    timestamps = [
        event.get("timestamp")
        for event in events
        if event.get("timestamp")
    ]

    if timestamps:

        state["last_timestamp"] = max(
            timestamps
        )

    return (
        new_events,
        returned_events,
        resolved_now,
    )


# ============================================================
# DISPLAY
# ============================================================

def print_section(title):

    print()

    print(
        f"============ {title} ============"
    )


def print_event_keys(title, keys):

    if not keys:
        return

    print_section(title)

    for key in sorted(keys):

        severity, score, message = parse_key(
            key
        )

        print(
            f"  [{severity:<9}] "
            f"+{score:<2} "
            f"{message}"
        )


# ============================================================
# MONITOR RUN
# ============================================================

def monitor_run():

    events = load_events()

    state = load_state()

    current_events = get_current_events(
        events,
        state,
    )

    (
        new_events,
        returned_events,
        resolved_events,
    ) = reconcile(
        current_events,
        state,
    )

    save_state(state)

    print()

    print(
        "===================================="
    )

    print(
        "       NEXUS EVENT STATE"
    )

    print(
        "===================================="
    )

    print()

    print(
        f"Active events:   "
        f"{len(state['active_events'])}"
    )

    print(
        f"Resolved events: "
        f"{len(state['resolved_events'])}"
    )

    print(
        f"New events:      "
        f"{len(new_events)}"
    )

    print(
        f"Returned events: "
        f"{len(returned_events)}"
    )

    print(
        f"Resolved now:    "
        f"{len(resolved_events)}"
    )

    print_event_keys(
        "NEW EVENTS",
        new_events,
    )

    print_event_keys(
        "RETURNED EVENTS",
        returned_events,
    )

    print_event_keys(
        "RESOLVED EVENTS",
        resolved_events,
    )

    print()

    print(
        "State saved:"
    )

    print(
        f"  {STATE_FILE}"
    )

    print()

    print(
        "===================================="
    )


# ============================================================
# MAIN
# ============================================================

def main():

    if len(sys.argv) != 2:

        print(
            "Usage:"
        )

        print(
            "  python3 -m scripts.agent.event_state "
            "--monitor-run"
        )

        sys.exit(1)

    if sys.argv[1] != "--monitor-run":

        print(
            "Usage:"
        )

        print(
            "  python3 -m scripts.agent.event_state "
            "--monitor-run"
        )

        sys.exit(1)

    monitor_run()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()

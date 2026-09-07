#!/usr/bin/env python3

import json
import os
from datetime import datetime, timezone
from pathlib import Path


NEXUS = Path.home() / "nexus"

HARDWARE_DIR = NEXUS / "hardware"

TELEMETRY_FILE = Path(
    os.environ.get(
        "NEXUS_TELEMETRY_FILE",
        str(
            HARDWARE_DIR
            / "telemetry.json"
        ),
    )
)

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

EVENT_LOG = (
    EVENT_DIR / "events.jsonl"
)

STATE_FILE = (
    EVENT_DIR / "telemetry_state.json"
)


THERMAL_SEVERITY = {
    "NORMAL": "INFO",
    "ELEVATED": "MEDIUM",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
    "UNKNOWN": "INFO",
}


def load_json(
    path,
    default,
):
    try:
        with path.open(
            encoding="utf-8"
        ) as file:
            return json.load(file)

    except (
        OSError,
        json.JSONDecodeError,
    ):
        return default


def load_state():
    state = {
        "cpu": "UNKNOWN",
        "gpu": "UNKNOWN",
        "tj": "UNKNOWN",
        "updated_at": None,
    }

    data = load_json(
        STATE_FILE,
        state,
    )

    if not isinstance(
        data,
        dict,
    ):
        return state

    state.update(data)

    return state


def save_state(state):
    STATE_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    STATE_FILE.write_text(
        json.dumps(
            state,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def append_event(
    severity,
    score,
    message,
):
    EVENT_LOG.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    record = {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "risk_level": (
            "HIGH"
            if severity in {
                "HIGH",
                "CRITICAL",
            }
            else (
                "LOW"
                if severity == "MEDIUM"
                else "NORMAL"
            )
        ),
        "event_score": score,
        "event_type": "system_health",
        "classification": "SYSTEM_HEALTH",
        "severity": severity,
        "score": score,
        "message": message,
    }

    with EVENT_LOG.open(
        "a",
        encoding="utf-8",
    ) as file:
        file.write(
            json.dumps(
                record
            )
            + "\n"
        )

    return record


def thermal_score(state):
    scores = {
        "NORMAL": 0,
        "ELEVATED": 15,
        "HIGH": 25,
        "CRITICAL": 50,
        "UNKNOWN": 0,
    }

    return scores.get(
        state,
        0,
    )


def build_message(
    sensor,
    previous,
    current,
    temperature,
):
    return (
        f"Thermal state changed on "
        f"{sensor.upper()}: "
        f"{previous} -> {current} "
        f"({temperature:.1f}C)"
    )


def process_sensor(
    sensor,
    temperature,
    current_state,
    previous_state,
):
    if current_state == "UNKNOWN":
        return False

    # First observation establishes the baseline.
    # Do not create an event for UNKNOWN -> NORMAL.
    if previous_state == "UNKNOWN":
        return False

    if previous_state == current_state:
        return False

    severity = THERMAL_SEVERITY.get(
        current_state,
        "INFO",
    )

    score = thermal_score(
        current_state
    )

    message = build_message(
        sensor,
        previous_state,
        current_state,
        temperature,
    )

    append_event(
        severity,
        score,
        message,
    )

    print(
        f"[{severity:<8}] "
        f"+{score:<2} "
        f"{message}",
        flush=True,
    )

    return True


def main():
    telemetry = load_json(
        TELEMETRY_FILE,
        {},
    )

    if not telemetry:
        raise SystemExit(
            "ERROR: telemetry.json not found or invalid."
        )

    temperatures = telemetry.get(
        "temperature_c",
        {},
    )

    states = telemetry.get(
        "thermal_state",
        {},
    )

    previous = load_state()

    current = {
        "cpu": states.get(
            "cpu",
            "UNKNOWN",
        ),
        "gpu": states.get(
            "gpu",
            "UNKNOWN",
        ),
        "tj": states.get(
            "tj",
            "UNKNOWN",
        ),
    }

    print(
        "============ NEXUS THERMAL STATE ============",
        flush=True,
    )

    changed = 0

    for sensor in (
        "cpu",
        "gpu",
        "tj",
    ):

        temperature = temperatures.get(
            sensor
        )

        current_state = current[
            sensor
        ]

        previous_state = previous.get(
            sensor,
            "UNKNOWN",
        )

        print(
            f"{sensor.upper():<5} "
            f"{temperature!s:<8} "
            f"{previous_state} -> "
            f"{current_state}",
            flush=True,
        )

        if process_sensor(
            sensor,
            temperature,
            current_state,
            previous_state,
        ):
            changed += 1

    current["updated_at"] = (
        telemetry.get(
            "generated_at"
        )
    )

    save_state(
        current
    )

    print(
        f"Thermal transitions: {changed}",
        flush=True,
    )


if __name__ == "__main__":
    main()

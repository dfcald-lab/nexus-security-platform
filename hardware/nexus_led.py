#!/usr/bin/env python3

import json
import time
import sys
from pathlib import Path

sys.path.insert(
    0,
    "/home/jetson/CubeNano-driver"
)

from CubeNanoLib import CubeNano


STATE_FILE = (
    Path.home()
    / "nexus"
    / "hardware"
    / "state.json"
)


COLORS = {
    "NORMAL": (0, 255, 0),
    "INFO": (0, 255, 255),
    "MEDIUM": (255, 255, 0),
    "HIGH": (255, 0, 0),
    "CRITICAL": (255, 0, 255),
}


def load_state():

    try:
        with STATE_FILE.open() as file:
            data = json.load(file)

        if isinstance(data, dict):
            return data

    except (
        OSError,
        json.JSONDecodeError,
    ):
        pass

    return {
        "severity": "INFO",
        "active_events": 0,
    }


def set_led(cube, severity, active_events):

    if active_events <= 0:
        color_name = "NORMAL"
    else:
        color_name = severity

    r, g, b = COLORS.get(
        color_name,
        COLORS["INFO"],
    )

    cube.set_Single_Color(
        255,
        r,
        g,
        b,
    )

    return color_name


def main():

    cube = CubeNano()
    last_state = None

    try:

        while True:

            state = load_state()

            severity = str(
                state.get(
                    "severity",
                    "INFO",
                )
            ).upper()

            active_events = int(
                state.get(
                    "active_events",
                    0,
                )
            )

            state_key = (
                severity,
                active_events,
            )

            if state_key != last_state:

                color = set_led(
                    cube,
                    severity,
                    active_events,
                )

                print(
                    f"NEXUS LED: {color}"
                )

                last_state = state_key

            time.sleep(1)

    except KeyboardInterrupt:

        cube.set_RGB_Effect(0)
        print("\nNEXUS LED stopped.")


if __name__ == "__main__":
    main()

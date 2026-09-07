#!/usr/bin/env python3

import json
import os
import sys
import time
import subprocess
from pathlib import Path

import psutil
from PIL import Image, ImageDraw, ImageFont
from luma.core.interface.serial import i2c
from luma.oled.device import ssd1306

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

HEALTH_FILE = (
    Path.home()
    / "nexus"
    / "hardware"
    / "health.json"
)


SEVERITY_ORDER = {
    "INFO": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}

LED_COLORS = {
    "NORMAL": (0, 255, 0),
    "INFO": (0, 255, 255),
    "MEDIUM": (255, 255, 0),
    "HIGH": (255, 0, 0),
    "CRITICAL": (255, 0, 255),
}

LED_NAMES = {
    "NORMAL": "GREEN",
    "INFO": "CYAN",
    "MEDIUM": "YELLOW",
    "HIGH": "RED",
    "CRITICAL": "PURPLE",
}


# ------------------------------------------------------------
# I2C hardware
# OLED = bus 7 / 0x3C
# CUBE = bus 7 / 0x0E
# ------------------------------------------------------------

serial = i2c(
    port=7,
    address=0x3C,
)

oled = ssd1306(
    serial,
    width=128,
    height=32,
)

cube = CubeNano(
    i2c_bus=7
)


FONT_BIG = ImageFont.truetype(
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    14,
)

FONT_MED = ImageFont.truetype(
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    12,
)


def write_hardware_health(
    oled_status=None,
    led_status=None,
    audio_status=None,
    error=None,
):
    health = {
        "overall": "UNKNOWN",
        "oled": "UNKNOWN",
        "led": "UNKNOWN",
        "audio": "UNKNOWN",
        "updated_at": time.time(),
        "error": None,
    }

    try:
        if HEALTH_FILE.exists():
            with HEALTH_FILE.open() as file:
                existing = json.load(file)

            if isinstance(existing, dict):
                for key in (
                    "overall",
                    "oled",
                    "led",
                    "audio",
                    "updated_at",
                    "error",
                ):
                    if key in existing:
                        health[key] = existing[key]

    except (
        OSError,
        json.JSONDecodeError,
    ):
        pass

    if oled_status is not None:
        health["oled"] = str(oled_status).upper()

    if led_status is not None:
        health["led"] = str(led_status).upper()

    if audio_status is not None:
        health["audio"] = str(audio_status).upper()

    if error is not None:
        health["error"] = str(error)

    elif oled_status == "ONLINE":
        # A successful OLED operation clears a stale OLED error.
        if (
            isinstance(health.get("error"), str)
            and (
                health["error"].startswith("OLED:")
                or health["error"].startswith("TEST: simulated OLED")
            )
        ):
            health["error"] = None

    elif led_status == "ONLINE":
        # A successful LED operation clears a stale LED error.
        if (
            isinstance(health.get("error"), str)
            and health["error"].startswith("LED:")
        ):
            health["error"] = None

    elif audio_status == "ONLINE":
        # Successful audio playback clears a stale audio error.
        if (
            isinstance(health.get("error"), str)
            and health["error"].startswith("AUDIO:")
        ):
            health["error"] = None

    statuses = (
        health["oled"],
        health["led"],
        health["audio"],
    )

    if "DEGRADED" in statuses:
        health["overall"] = "DEGRADED"
    elif all(
        status == "ONLINE"
        for status in statuses
    ):
        health["overall"] = "HEALTHY"
    else:
        health["overall"] = "UNKNOWN"

    health["updated_at"] = time.time()

    HEALTH_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    HEALTH_FILE.write_text(
        json.dumps(
            health,
            indent=2,
        )
        + "\n"
    )


def load_state():

    state = {
        "status": "ONLINE",
        "risk": "LOW",
        "severity": "INFO",
        "classification": "NORMAL",
        "active_events": 0,
        "actionable_events": 0,
        "devices": 0,
        "top_event": "NO ALERT",
    }

    try:
        with STATE_FILE.open() as file:
            data = json.load(file)

        if isinstance(data, dict):
            state.update(data)

    except (
        OSError,
        json.JSONDecodeError,
    ):
        pass

    return state


def center_text(draw, text, font, y):
    box = draw.textbbox(
        (0, 0),
        text,
        font=font,
    )

    width = box[2] - box[0]

    x = max(
        0,
        (128 - width) // 2,
    )

    draw.text(
        (x, y),
        text,
        font=font,
        fill=255,
    )


def show_screen(lines):
    image = Image.new(
        "1",
        (128, 32),
        0,
    )

    draw = ImageDraw.Draw(image)

    for text, font, y in lines:
        center_text(
            draw,
            text,
            font,
            y,
        )

    try:
        oled.display(image)

        write_hardware_health(
            oled_status="ONLINE",
        )

    except (
        OSError,
        TimeoutError,
    ) as error:
        print(
            f"OLED: DISPLAY FAILED: {error}",
            flush=True,
        )

        write_hardware_health(
            oled_status="DEGRADED",
            error=f"OLED: {error}",
        )


def set_led(severity, active_events):
    if active_events <= 0:
        state_name = "NORMAL"
    else:
        state_name = severity

    r, g, b = LED_COLORS.get(
        state_name,
        LED_COLORS["INFO"],
    )

    try:
        cube.set_Single_Color(
            255,
            r,
            g,
            b,
        )

        write_hardware_health(
            led_status="ONLINE",
        )

    except (
        OSError,
        TimeoutError,
    ) as error:
        print(
            f"LED: DISPLAY FAILED: {error}",
            flush=True,
        )

        write_hardware_health(
            led_status="DEGRADED",
            error=f"LED: {error}",
        )

    return state_name


def show_dashboard(state):
    status = str(
        state.get(
            "status",
            "ONLINE",
        )
    ).upper()

    risk = str(
        state.get(
            "risk",
            "LOW",
        )
    ).upper()

    show_screen([
        (
            "NEXUS",
            FONT_BIG,
            0,
        ),
        (
            f"{status}  RISK {risk}",
            FONT_MED,
            18,
        ),
    ])


def show_network(state):
    devices = int(
        state.get(
            "devices",
            0,
        )
    )

    events = int(
        state.get(
            "active_events",
            0,
        )
    )

    show_screen([
        (
            "NETWORK",
            FONT_BIG,
            0,
        ),
        (
            f"DEV {devices}     EVT {events}",
            FONT_MED,
            18,
        ),
    ])


def show_system(cpu, ram):
    show_screen([
        (
            "SYSTEM",
            FONT_BIG,
            0,
        ),
        (
            f"CPU {cpu:.0f}%     RAM {ram:.0f}%",
            FONT_MED,
            18,
        ),
    ])


def compact_event(message):
    message = str(message).upper()

    replacements = {
        "MAC ADDED TO DEVICE": "MAC ADDED",
        "MAC REMOVED FROM DEVICE": "MAC REMOVED",
        "DEVICE MOVED": "DEVICE MOVE",
        "NEW NETWORK DEVICE DETECTED": "NEW DEVICE",
        "MAC IDENTITY CHANGED ON": "MAC CHANGE",
        "MAC COUNT CHANGED ON PORT": "MAC COUNT",
        "NETWORK HEALTH METRIC CHANGED": "HEALTH CHANGE",
        "DEVICE STATE CHANGED": "DEVICE CHANGE",
    }

    for long_text, short_text in replacements.items():
        if message.startswith(long_text):
            return short_text

    return message[:15]


def show_alert(state):
    severity = str(
        state.get(
            "severity",
            "INFO",
        )
    ).upper()

    message = compact_event(
        state.get(
            "top_event",
            "ALERT",
        )
    )

    show_screen([
        (
            f"ALERT {severity}",
            FONT_BIG,
            0,
        ),
        (
            message,
            FONT_MED,
            18,
        ),
    ])


def highest_actionable_severity(state):
    severity = str(
        state.get(
            "severity",
            "INFO",
        )
    ).upper()

    if severity not in SEVERITY_ORDER:
        severity = "INFO"

    return severity

def play_critical_alert():
    try:
        env = os.environ.copy()
        env["XDG_RUNTIME_DIR"] = "/run/user/1000"
        env["PULSE_SERVER"] = "unix:/run/user/1000/pulse/native"

        sound = [
            "paplay",
            "--device=alsa_output.platform-3510000.hda.hdmi-stereo",
            "/usr/share/sounds/freedesktop/stereo/message-new-instant.oga",
        ]

        for count in range(2):
            result = subprocess.run(
                sound,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
                env=env,
            )

            if result.returncode != 0:
                error_text = (
                    f"AUDIO: PLAYBACK FAILED "
                    f"({result.returncode})"
                )

                print(
                    error_text,
                    flush=True,
                )

                if result.stderr:
                    print(
                        f"AUDIO ERROR: {result.stderr.strip()}",
                        flush=True,
                    )

                write_hardware_health(
                    audio_status="DEGRADED",
                    error=error_text,
                )

                return False

            if count == 0:
                time.sleep(0.7)

        print(
            "AUDIO: CRITICAL ALERT PLAYED x2",
            flush=True,
        )

        write_hardware_health(
            audio_status="ONLINE",
        )

        return True

    except (
        FileNotFoundError,
        subprocess.TimeoutExpired,
    ) as error:
        print(
            f"AUDIO: CRITICAL ALERT FAILED: {error}",
            flush=True,
        )

        write_hardware_health(
            audio_status="DEGRADED",
            error=f"AUDIO: {error}",
        )

        return False


def main():
    print(
        "NEXUS HARDWARE NODE ONLINE",
        flush=True,
    )

    # Start with honest hardware-health state.
    # Components become ONLINE only after a successful operation.
    # Audio remains UNKNOWN until a real alert is successfully played.
    write_hardware_health(
        oled_status="UNKNOWN",
        led_status="UNKNOWN",
        audio_status="UNKNOWN",
        error=None,
    )

    last_state_key = None
    cpu_samples = []
    ram_samples = []

    try:
        while True:
            state = load_state()

            severity = highest_actionable_severity(
                state
            )

            active_events = int(
                state.get(
                    "active_events",
                    0,
                )
            )

            actionable_events = int(
                state.get(
                    "actionable_events",
                    0,
                )
            )

            state_key = (
                severity,
                actionable_events,
                state.get(
                    "top_event",
                    "",
                ),
            )

            if state_key != last_state_key:

                if actionable_events <= 0:
                    hardware_state = "NORMAL"
                else:
                    hardware_state = severity
                if (
                    actionable_events > 0
                    and severity == "CRITICAL"
                ):
                    print(
                        "AUDIO: CRITICAL ALERT",
                        flush=True,
                    )

                    play_critical_alert()

                led_state = set_led(
                    severity,
                    actionable_events,
                )

                if (
                    actionable_events > 0
                    and severity in {
                        "MEDIUM",
                        "HIGH",
                        "CRITICAL",
                    }
                ):
                    oled_mode = "ALERT"
                else:
                    oled_mode = "DASHBOARD"

                print(
                    f"NEXUS STATE: {hardware_state}",
                    flush=True,
                )

                print(
                    f"LED: {LED_NAMES.get(led_state, led_state)}",
                    flush=True,
                )

                print(
                    f"OLED: {oled_mode}",
                    flush=True,
                )

                last_state_key = state_key

            cpu = psutil.cpu_percent(interval=0.1)
            ram = psutil.virtual_memory().percent

            cpu_samples.append(cpu)
            ram_samples.append(ram)

            if len(cpu_samples) > 5:
                cpu_samples.pop(0)

            if len(ram_samples) > 5:
                ram_samples.pop(0)

            smooth_cpu = sum(cpu_samples) / len(cpu_samples)
            smooth_ram = sum(ram_samples) / len(ram_samples)

            # Actionable incidents dominate the OLED rotation.
            # Keep the alert visible, while still showing useful
            # network and system telemetry between alert screens.
            actionable = (
                actionable_events > 0
                and severity in {
                    "MEDIUM",
                    "HIGH",
                    "CRITICAL",
                }
            )

            if actionable:
                show_alert(state)
                time.sleep(5)

                show_network(state)
                time.sleep(3)

                show_alert(state)
                time.sleep(5)

                show_system(
                    smooth_cpu,
                    smooth_ram,
                )
                time.sleep(3)

            else:
                show_dashboard(state)
                time.sleep(3)

                show_network(state)
                time.sleep(3)

                show_system(
                    smooth_cpu,
                    smooth_ram,
                )
                time.sleep(3)

    except KeyboardInterrupt:

        print(
            "NEXUS HARDWARE NODE STOPPING",
            flush=True,
        )

    finally:

        cube.set_RGB_Effect(0)


if __name__ == "__main__":
    main()

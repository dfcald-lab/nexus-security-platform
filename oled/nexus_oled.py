#!/usr/bin/env python3

import json
import sys
import time
from pathlib import Path

import psutil
from PIL import Image, ImageDraw, ImageFont
from luma.core.interface.serial import i2c
from luma.oled.device import ssd1306

# Yahboom CUBE driver
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

# ------------------------------------------------------------
# OLED
# ------------------------------------------------------------

serial = i2c(
    port=7,
    address=0x3C,
)

device = ssd1306(serial)

FONT_BIG = ImageFont.truetype(
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    18,
)

FONT_MED = ImageFont.truetype(
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    14,
)

# ------------------------------------------------------------
# LED
# ------------------------------------------------------------

cube = CubeNano()

LED_COLORS = {
    "NORMAL":  (0, 255, 0),
    "INFO":    (0, 255, 255),
    "MEDIUM":  (255, 255, 0),
    "HIGH":    (255, 0, 0),
    "CRITICAL": (255, 0, 255),
}


def load_state():

    state = {
        "status": "ONLINE",
        "risk": "LOW",
        "severity": "INFO",
        "active_events": 0,
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


def set_led(severity, active_events):

    if active_events <= 0:
        color = LED_COLORS["NORMAL"]
    else:
        color = LED_COLORS.get(
            severity,
            LED_COLORS["INFO"],
        )

    r, g, b = color

    cube.set_Single_Color(
        255,
        r,
        g,
        b,
    )


def center_text(draw, text, font, y):

    box = draw.textbbox(
        (0, 0),
        text,
        font=font,
    )

    width = box[2] - box[0]

    x = (128 - width) // 2

    draw.text(
        (x, y),
        text,
        font=font,
        fill=255,
    )


def show_screen(lines):

    image = Image.new(
        "1",
        (128, 64),
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

    device.display(image)


def dashboard(state):

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
        ("NEXUS", FONT_BIG, 0),
        (status, FONT_BIG, 22),
        (f"RISK {risk}", FONT_MED, 48),
    ])


def network(state):

    devices = state.get(
        "devices",
        0,
    )

    events = state.get(
        "active_events",
        0,
    )

    show_screen([
        ("NETWORK", FONT_BIG, 0),
        (f"DEVICES {devices}", FONT_MED, 24),
        (f"EVENTS {events}", FONT_MED, 44),
    ])


def system():

    cpu = psutil.cpu_percent(
        interval=0.1
    )

    ram = psutil.virtual_memory().percent

    show_screen([
        ("SYSTEM", FONT_BIG, 0),
        (f"CPU {cpu:.0f}%", FONT_MED, 24),
        (f"RAM {ram:.0f}%", FONT_MED, 44),
    ])


def alert(state):

    severity = str(
        state.get(
            "severity",
            "INFO",
        )
    ).upper()

    message = str(
        state.get(
            "top_event",
            "ALERT",
        )
    ).upper()

    replacements = {
        "DEVICE MOVED": "MOVE",
        "NEW NETWORK DEVICE DETECTED": "NEW DEVICE",
        "MAC REMOVED FROM DEVICE": "MAC REMOVED",
        "MAC COUNT CHANGED ON PORT": "MAC CHANGE",
        "NETWORK HEALTH METRIC CHANGED": "HEALTH",
        "MAC IDENTITY CHANGED ON": "MAC CHANGE",
        "DEVICE STATE CHANGED": "DEVICE CHANGE",
    }

    for long_text, short_text in replacements.items():

        if message.startswith(long_text):
            message = short_text
            break

    if len(message) > 13:
        message = message[:13]

    show_screen([
        ("NEXUS ALERT", FONT_MED, 0),
        (severity, FONT_BIG, 20),
        (message, FONT_MED, 47),
    ])


# ------------------------------------------------------------
# MAIN HARDWARE LOOP
# ------------------------------------------------------------

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

        # LEDs always represent current Nexus severity.
        set_led(
            severity,
            active_events,
        )

        # Alert screen gets priority.
        if active_events > 0:

            alert(state)
            time.sleep(3)

        dashboard(state)
        time.sleep(3)

        network(state)
        time.sleep(3)

        system()
        time.sleep(3)

except KeyboardInterrupt:

    cube.set_RGB_Effect(0)

    print("\nNEXUS hardware stopped.")

#!/usr/bin/env python3

import html
import json
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

STATE = Path.home() / "nexus" / "hardware" / "state.json"

AI_RESULT = (
    Path.home()
    / "nexus"
    / "monitoring"
    / "intelligence"
    / "ai_result.json"
)

AI_TRIGGER_STATE = (
    Path.home()
    / "nexus"
    / "monitoring"
    / "intelligence"
    / "ai_trigger_state.json"
)

AI_VALIDATION_STATE = (
    Path.home()
    / "nexus"
    / "monitoring"
    / "intelligence"
    / "ai_validation_state.json"
)

HARDWARE_HEALTH = (
    Path.home()
    / "nexus"
    / "hardware"
    / "health.json"
)

HOST = "127.0.0.1"
PORT = 8787

SEVERITY_ORDER = {
    "INFO": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}


def load_state():
    default = {
        "status": "UNKNOWN",
        "risk": "UNKNOWN",
        "severity": "INFO",
        "active_events": 0,
        "devices": 0,
        "top_event": "NO DATA",
        "network": {},
        "network_devices": [],
        "active_event_details": [],
    }

    try:
        with STATE.open() as file:
            data = json.load(file)

        if isinstance(data, dict):
            default.update(data)

    except (OSError, json.JSONDecodeError):
        pass

    return default

def load_ai_result():
    default = {
        "model": None,
        "generated_at": None,
        "source_intelligence_at": None,
        "source_last_event_at": None,
        "status": "UNAVAILABLE",
        "result": {},
    }

    try:
        with AI_RESULT.open() as file:
            data = json.load(file)

        if isinstance(data, dict):
            default.update(data)

    except (OSError, json.JSONDecodeError):
        pass

    return default

def load_ai_trigger_state():
    default = {
        "trigger_status": "UNKNOWN",
        "last_run_at": None,
        "current_seen_at": None,
    }

    try:
        with AI_TRIGGER_STATE.open() as file:
            data = json.load(file)

        if isinstance(data, dict):
            default.update(data)

    except (OSError, json.JSONDecodeError):
        pass

    return default

def load_ai_validation_state():
    default = {
        "status": "UNKNOWN",
        "attempted_at": None,
        "source_intelligence_at": None,
        "error": None,
    }

    try:
        with AI_VALIDATION_STATE.open() as file:
            data = json.load(file)

        if isinstance(data, dict):
            default.update(data)

    except (OSError, json.JSONDecodeError):
        pass

    return default


def load_hardware_health():
    default = {
        "overall": "UNKNOWN",
        "oled": "UNKNOWN",
        "led": "UNKNOWN",
        "audio": "UNKNOWN",
        "updated_at": None,
        "error": None,
    }

    try:
        with HARDWARE_HEALTH.open() as file:
            data = json.load(file)

        if isinstance(data, dict):
            default.update(data)

    except (OSError, json.JSONDecodeError):
        pass

    return default


def esc(value):
    return html.escape(str(value))


def severity_class(value):
    severity = str(value).upper()

    if severity == "CRITICAL":
        return "critical"

    if severity == "HIGH":
        return "high"

    if severity == "MEDIUM":
        return "medium"

    if severity == "INFO":
        return "info"

    return "normal"


def device_row(device):
    device_id = esc(
        device.get(
            "device_id",
            "UNKNOWN",
        )
    )

    device_type = esc(
        device.get(
            "device_type",
            "UNKNOWN",
        )
    )

    vendor = esc(
        device.get(
            "vendor",
            "Unknown",
        )
    )

    ip = esc(
        device.get(
            "ip",
            "Unknown",
        )
    )

    port = esc(
        device.get(
            "port",
            "Unknown",
        )
    )

    vlan = esc(
        device.get(
            "vlan",
            "Unknown",
        )
    )

    return (
        '<div class="device-row">'
        f'<div class="device-title">{device_type} '
        f'<span>{vendor}</span></div>'
        f'<div class="device-meta">'
        f'{ip} · {port} · VLAN {vlan}'
        '</div>'
        f'<a class="device-link" href="/device/{device_id}">'
        'VIEW DETAILS →'
        '</a>'
        '</div>'
    )


def format_timestamp(value):
    if not value:
        return "UNKNOWN"

    try:
        timestamp = datetime.fromisoformat(
            str(value).replace(
                "Z",
                "+00:00",
            )
        )

        return timestamp.strftime(
            "%Y-%m-%d %H:%M UTC"
        )

    except ValueError:
        return str(value)


def format_duration(seconds, active=False):
    if seconds is None:
        return "IN PROGRESS" if active else "UNKNOWN"

    try:
        seconds = max(
            0,
            int(seconds),
        )
    except (TypeError, ValueError):
        return "UNKNOWN"

    days, remainder = divmod(
        seconds,
        86400,
    )

    hours, remainder = divmod(
        remainder,
        3600,
    )

    minutes, seconds = divmod(
        remainder,
        60,
    )

    parts = []

    if days:
        parts.append(f"{days}d")

    if hours:
        parts.append(f"{hours}h")

    if minutes:
        parts.append(f"{minutes}m")

    if seconds or not parts:
        parts.append(f"{seconds}s")

    return " ".join(parts)


def event_row(event, index):
    severity = esc(
        event.get(
            "severity",
            "INFO",
        )
    )

    message = esc(
        event.get(
            "message",
            "NO DATA",
        )
    )

    return (
        '<div class="event-row">'
        f'<div class="event-severity {severity_class(severity)}">'
        f'{severity}</div>'
        f'<div class="event-message">{message}</div>'
        f'<a class="device-link" href="/event/{index}">'
        'VIEW DETAILS →'
        '</a>'
        '</div>'
    )


class Handler(BaseHTTPRequestHandler):

    def do_GET(self):

        if self.path == "/events":

            state = load_state()

            active_events = state.get(
                "active_event_details",
                [],
            )

            resolved_events = state.get(
                "resolved_event_details",
                [],
            )

            if not isinstance(active_events, list):
                active_events = []

            if not isinstance(resolved_events, list):
                resolved_events = []

            def history_row(event, href, state_label):
                incident = esc(
                    event.get(
                        "incident_id",
                        "UNKNOWN",
                    )
                )

                severity = esc(
                    event.get(
                        "severity",
                        "INFO",
                    )
                )

                message = esc(
                    event.get(
                        "message",
                        "NO DATA",
                    )
                )

                detected_at = esc(
                    format_timestamp(
                        event.get(
                            "detected_at",
                        )
                    )
                )

                resolved_at = esc(
                    format_timestamp(
                        event.get(
                            "resolved_at",
                        )
                    )
                )

                duration = esc(
                    format_duration(
                        event.get(
                            "duration_seconds",
                        ),
                        active=state_label == "ACTIVE",
                    )
                )

                activation_count = esc(
                    event.get(
                        "activation_count",
                        1,
                    )
                )

                if state_label == "ACTIVE":
                    lifecycle = (
                        f"ACTIVE · {detected_at} · "
                        f"{duration} · "
                        f"ACTIVATIONS {activation_count}"
                    )
                else:
                    lifecycle = (
                        f"RESOLVED · {detected_at} · "
                        f"{resolved_at} · "
                        f"{duration}"
                    )

                return (
                    '<div class="history-row">'
                    f'<div class="history-severity '
                    f'{severity_class(severity)}">{severity}</div>'
                    f'<div class="history-incident">{incident}</div>'
                    f'<div class="history-message">{message}</div>'
                    f'<div class="history-state">{lifecycle}</div>'
                    f'<a class="device-link" href="{href}">'
                    'VIEW DETAILS →'
                    '</a>'
                    '</div>'
                )

            active_rows = ""

            valid_active = [
                event
                for event in active_events
                if isinstance(event, dict)
            ]

            valid_active.sort(
                key=lambda event: (
                    SEVERITY_ORDER.get(
                        str(
                            event.get(
                                "severity",
                                "INFO",
                            )
                        ).upper(),
                        0,
                    ),
                    str(
                        event.get(
                            "detected_at",
                            "",
                        )
                    ),
                ),
                reverse=True,
            )

            for index, event in enumerate(valid_active):
                incident_id = event.get(
                    "incident_id",
                )

                href = (
                    f"/event/{incident_id}"
                    if incident_id
                    else f"/event/{index}"
                )

                active_rows += history_row(
                    event,
                    href,
                    "ACTIVE",
                )

            if not active_rows:
                active_rows = (
                    '<div class="muted">No active events</div>'
                )

            resolved_rows = ""

            valid_resolved = [
                event
                for event in resolved_events
                if isinstance(event, dict)
            ]

            valid_resolved.sort(
                key=lambda event: (
                    str(
                        event.get(
                            "detected_at",
                            "",
                        )
                    ),
                    int(
                        event.get(
                            "event_id",
                            0,
                        )
                    ),
                ),
                reverse=True,
            )

            for event in valid_resolved:
                event_id = event.get(
                    "event_id",
                    0,
                )

                incident_id = event.get(
                    "incident_id",
                )

                href = (
                    f"/event/resolved/{incident_id}"
                    if incident_id
                    else f"/event/resolved/{event_id}"
                )

                resolved_rows += history_row(
                    event,
                    href,
                    "RESOLVED",
                )

            if not resolved_rows:
                resolved_rows = (
                    '<div class="muted">'
                    'No resolved events'
                    '</div>'
                )

            html_page = f"""<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NEXUS Events</title>

<style>
body {{
    margin: 0;
    background: #080b10;
    color: #f5f7fa;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}}

main {{
    width: min(100% - 24px, 1500px);
    margin: auto;
    padding: 24px 0 48px;
}}

a {{
    color: #58a6ff;
    text-decoration: none;
}}

.card {{
    margin-top: 14px;
    background: #11161d;
    border: 1px solid #222b35;
    border-radius: 14px;
    padding: 16px;
}}

.section-title {{
    font-size: 18px;
    font-weight: 750;
}}

.history-row {{
    padding: 12px 0;
    border-top: 1px solid #222b35;
}}

.history-row:first-child {{
    border-top: 0;
}}

.history-severity {{
    font-size: 11px;
    font-weight: 800;
    letter-spacing: .08em;
}}

.history-incident {{
    margin-top: 3px;
    color: #aab4bf;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: .04em;
}}

.history-message {{
    margin-top: 4px;
    font-size: 14px;
    line-height: 1.4;
    overflow-wrap: anywhere;
}}

.history-state {{
    margin-top: 5px;
    color: #7f8a96;
    font-size: 11px;
    letter-spacing: .08em;
}}

.device-link {{
    display: inline-block;
    margin-top: 7px;
    color: #58a6ff;
    font-size: 11px;
    font-weight: 700;
}}

.muted {{
    color: #7f8a96;
    font-size: 13px;
}}

.high {{
    color: #f85149;
}}

.medium {{
    color: #e3b341;
}}

.info {{
    color: #58a6ff;
}}

.critical {{
    color: #ff7b72;
}}

@media (min-width: 700px) {{
    main {{
        width: min(100% - 48px, 1100px);
        padding-top: 32px;
    }}

    .card {{
        padding: 20px;
    }}

    .history-row {{
        display: grid;
        grid-template-columns: 90px minmax(150px, 220px) minmax(0, 1fr) auto;
        align-items: center;
        column-gap: 16px;
    }}

    .history-message,
    .history-state,
    .device-link {{
        margin-top: 0;
    }}
}}

@media (min-width: 1100px) {{
    main {{
        width: min(100% - 64px, 1500px);
    }}

    .grid {{
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 14px;
    }}

    .section {{
        margin-top: 14px;
    }}
}}

</style>
</head>

<body>
<main>

<a href="/">← NEXUS Dashboard</a>

<h1>NEXUS EVENTS</h1>

<div class="card">
    <div class="section-title">Active</div>
    {active_rows}
</div>

<div class="card">
    <div class="section-title">Resolved</div>
    {resolved_rows}
</div>

</main>
</body>
</html>
"""

            body = html_page.encode()

            self.send_response(200)

            self.send_header(
                "Content-Type",
                "text/html; charset=utf-8",
            )

            self.send_header(
                "Content-Length",
                str(len(body)),
            )

            self.end_headers()

            self.wfile.write(body)

            return

        if self.path.startswith("/event/resolved/"):

            event_id_text = self.path.split(
                "/event/resolved/",
                1,
            )[1]

            try:
                event_id = int(event_id_text)
            except ValueError:
                event_id = -1

            state = load_state()

            events = state.get(
                "resolved_event_details",
                [],
            )

            if not isinstance(events, list):
                events = []

            event = next(
                (
                    item
                    for item in events
                    if isinstance(item, dict)
                    and (
                        (
                            event_id >= 0
                            and int(
                                item.get(
                                    "event_id",
                                    -1,
                                )
                            ) == event_id
                        )
                        or
                        (
                            str(
                                item.get(
                                    "incident_id",
                                    "",
                                )
                            ) == event_id_text
                        )
                    )
                ),
                None,
            )

            if event is None:

                self.send_response(404)
                self.send_header(
                    "Content-Type",
                    "text/html; charset=utf-8",
                )
                self.end_headers()

                self.wfile.write(
                    b"<h1>NEXUS: Resolved Event Not Found</h1>"
                )

                return

            incident = esc(
                event.get(
                    "incident_id",
                    "UNKNOWN",
                )
            )

            detected_at = esc(
                format_timestamp(
                    event.get(
                        "detected_at",
                    )
                )
            )

            resolved_at = esc(
                format_timestamp(
                    event.get(
                        "resolved_at",
                    )
                )
            )

            duration = esc(
                format_duration(
                    event.get(
                        "duration_seconds",
                    )
                )
            )

            activation_count = esc(
                event.get(
                    "activation_count",
                    1,
                )
            )

            resolution_status = esc(
                event.get(
                    "resolution_status",
                    "UNKNOWN",
                )
            )

            event_severity = esc(
                event.get(
                    "severity",
                    "INFO",
                )
            )

            if resolved_at == "UNKNOWN":
                resolved_label = "HISTORICAL"
                resolved_note = (
                    "Resolution time unavailable"
                )
            else:
                resolved_label = "RESOLVED"
                resolved_note = (
                    f"Duration: {duration}"
                )

            score = esc(
                event.get(
                    "score",
                    0,
                )
            )

            message = esc(
                event.get(
                    "message",
                    "NO DATA",
                )
            )

            html_page = f"""<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NEXUS Resolved Event</title>

<style>
body {{
    margin: 0;
    background: #080b10;
    color: #f5f7fa;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}}

main {{
    width: min(100% - 24px, 1500px);
    margin: auto;
    padding: 24px 0 48px;
}}

a {{
    color: #58a6ff;
    text-decoration: none;
}}

.card {{
    margin-top: 16px;
    background: #11161d;
    border: 1px solid #222b35;
    border-radius: 14px;
    padding: 18px;
}}

.label {{
    color: #7f8a96;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: .12em;
    text-transform: uppercase;
    margin-top: 14px;
}}

.value {{
    margin-top: 5px;
    font-size: 20px;
}}

.message {{
    margin-top: 8px;
    font-size: 16px;
    line-height: 1.5;
    overflow-wrap: anywhere;
}}

.timeline {{
    margin-top: 22px;
    padding: 4px 0 4px 8px;
}}

.timeline-item {{
    position: relative;
    padding: 0 0 22px 28px;
}}

.timeline-item:last-child {{
    padding-bottom: 0;
}}

.timeline-item::before {{
    content: "";
    position: absolute;
    left: 5px;
    top: 6px;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: #58a6ff;
    border: 2px solid #11161d;
}}

.timeline-item::after {{
    content: "";
    position: absolute;
    left: 9px;
    top: 20px;
    bottom: 0;
    width: 2px;
    background: #26303a;
}}

.timeline-item:last-child::after {{
    display: none;
}}

.timeline-title {{
    font-size: 13px;
    font-weight: 800;
    letter-spacing: .08em;
}}

.timeline-time {{
    margin-top: 4px;
    color: #aab4bf;
    font-size: 13px;
}}

.timeline-note {{
    margin-top: 3px;
    color: #7f8a96;
    font-size: 12px;
}}

.progress-card {{
    margin-top: 18px;
    padding: 14px;
    background: #0d1218;
    border: 1px solid #26303a;
    border-radius: 10px;
}}

.progress-title {{
    font-size: 12px;
    font-weight: 800;
    letter-spacing: .08em;
}}

.progress-time {{
    margin-top: 5px;
    font-size: 17px;
    font-weight: 700;
}}

.progress-note {{
    margin-top: 4px;
    color: #7f8a96;
    font-size: 12px;
}}

@media (min-width: 700px) {{
    main {{
        width: min(100% - 48px, 1000px);
        padding-top: 32px;
    }}

    .card {{
        padding: 24px;
    }}

    .timeline {{
        max-width: 800px;
    }}

    .message {{
        max-width: 900px;
    }}
}}

@media (min-width: 1100px) {{
    main {{
        width: min(100% - 64px, 1100px);
    }}

    .card {{
        padding: 28px;
    }}
}}

</style>
</head>

<body>
<main>

<a href="/events">← NEXUS Events</a>

<h1>RESOLVED EVENT</h1>

<div class="card">

<div class="label">Incident</div>
<div class="value">{incident}</div>

<div class="label">Severity</div>
<div class="value">{event_severity}</div>

<div class="label">Score</div>
<div class="value">{score}</div>

<div class="timeline">

<div class="timeline-item">
    <div class="timeline-title">DETECTED</div>
    <div class="timeline-time">{detected_at}</div>
</div>

<div class="timeline-item">
    <div class="timeline-title">ACTIVE</div>
    <div class="timeline-time">
        {activation_count} activation(s)
    </div>
    <div class="timeline-note">
        Incident was tracked by NEXUS
    </div>
</div>

<div class="timeline-item">
    <div class="timeline-title">{resolved_label}</div>
    <div class="timeline-time">{resolved_at}</div>
    <div class="timeline-note">{resolved_note}</div>
</div>

</div>

<div class="label">Message</div>
<div class="message">{message}</div>

</div></div>

</main>
</body>
</html>
"""

            body = html_page.encode()

            self.send_response(200)

            self.send_header(
                "Content-Type",
                "text/html; charset=utf-8",
            )

            self.send_header(
                "Content-Length",
                str(len(body)),
            )

            self.end_headers()

            self.wfile.write(body)

            return

        if self.path.startswith("/event/"):

            event_id = self.path.split(
                "/event/",
                1,
            )[1]

            state = load_state()

            events = state.get(
                "active_event_details",
                [],
            )

            if not isinstance(events, list):
                events = []

            event = None

            try:
                index = int(event_id)
            except ValueError:
                index = -1

            if 0 <= index < len(events):
                event = events[index]

            else:
                event = next(
                    (
                        item
                        for item in events
                        if isinstance(item, dict)
                        and str(
                            item.get(
                                "incident_id",
                                "",
                            )
                        ) == event_id
                    ),
                    None,
                )

            if event is None:

                self.send_response(404)
                self.send_header(
                    "Content-Type",
                    "text/html; charset=utf-8",
                )
                self.end_headers()

                self.wfile.write(
                    b"<h1>NEXUS: Event Not Found</h1>"
                )

                return

            incident = esc(
                event.get(
                    "incident_id",
                    "UNKNOWN",
                )
            )

            detected_at = esc(
                format_timestamp(
                    event.get(
                        "detected_at",
                    )
                )
            )

            duration = esc(
                format_duration(
                    event.get(
                        "duration_seconds",
                    ),
                    active=True,
                )
            )

            activation_count = esc(
                event.get(
                    "activation_count",
                    1,
                )
            )

            event_severity = esc(
                event.get(
                    "severity",
                    "INFO",
                )
            )

            score = esc(
                event.get(
                    "score",
                    0,
                )
            )

            message = esc(
                event.get(
                    "message",
                    "NO DATA",
                )
            )

            html_page = f"""<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NEXUS Event</title>

<style>
body {{
    margin: 0;
    background: #080b10;
    color: #f5f7fa;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}}

main {{
    width: min(100% - 20px, 700px);
    margin: auto;
    padding: 20px 0 40px;
}}

a {{
    color: #58a6ff;
    text-decoration: none;
}}

.card {{
    margin-top: 16px;
    background: #11161d;
    border: 1px solid #222b35;
    border-radius: 14px;
    padding: 18px;
}}

.label {{
    color: #7f8a96;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: .12em;
    text-transform: uppercase;
    margin-top: 14px;
}}

.value {{
    margin-top: 5px;
    font-size: 20px;
}}

.message {{
    margin-top: 8px;
    font-size: 16px;
    line-height: 1.5;
    overflow-wrap: anywhere;
}}

.timeline {{
    margin-top: 22px;
    padding: 4px 0 4px 8px;
}}

.timeline-item {{
    position: relative;
    padding: 0 0 22px 28px;
}}

.timeline-item:last-child {{
    padding-bottom: 0;
}}

.timeline-item::before {{
    content: "";
    position: absolute;
    left: 5px;
    top: 6px;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: #58a6ff;
    border: 2px solid #11161d;
}}

.timeline-item::after {{
    content: "";
    position: absolute;
    left: 9px;
    top: 20px;
    bottom: 0;
    width: 2px;
    background: #26303a;
}}

.timeline-item:last-child::after {{
    display: none;
}}

.timeline-title {{
    font-size: 13px;
    font-weight: 800;
    letter-spacing: .08em;
}}

.timeline-time {{
    margin-top: 4px;
    color: #aab4bf;
    font-size: 13px;
}}

.timeline-note {{
    margin-top: 3px;
    color: #7f8a96;
    font-size: 12px;
}}

.progress-card {{
    margin-top: 18px;
    padding: 14px;
    background: #0d1218;
    border: 1px solid #26303a;
    border-radius: 10px;
}}

.progress-title {{
    font-size: 12px;
    font-weight: 800;
    letter-spacing: .08em;
}}

.progress-time {{
    margin-top: 5px;
    font-size: 17px;
    font-weight: 700;
}}

.progress-note {{
    margin-top: 4px;
    color: #7f8a96;
    font-size: 12px;
}}

.severity {{
    font-weight: 800;
}}

h1 {{
    margin-bottom: 0;
}}
</style>
</head>

<body>
<main>

<a href="/">← NEXUS Dashboard</a>

<h1>EVENT DETAIL</h1>

<div class="card">

<div class="label">Incident</div>
<div class="value">{incident}</div>

<div class="label">Severity</div>
<div class="value severity">{event_severity}</div>

<div class="label">Score</div>
<div class="value">{score}</div>

<div class="timeline">

<div class="timeline-item">
    <div class="timeline-title">DETECTED</div>
    <div class="timeline-time">{detected_at}</div>
</div>

<div class="timeline-item">
    <div class="timeline-title">ACTIVE</div>
    <div class="timeline-time">
        {activation_count} activation(s)
    </div>
    <div class="timeline-note">
        Incident is currently being tracked by NEXUS
    </div>
</div>

</div>

<div class="progress-card">
    <div class="progress-title">● IN PROGRESS</div>
    <div class="progress-time">Monitoring continuously</div>
    <div class="progress-note">
        Duration: {duration} · Resolution pending
    </div>
</div>

<div class="label">Message</div>
<div class="message">{message}</div>

</div>
</main>
</body>
</html>
"""

            body = html_page.encode()

            self.send_response(200)

            self.send_header(
                "Content-Type",
                "text/html; charset=utf-8",
            )

            self.send_header(
                "Content-Length",
                str(len(body)),
            )

            self.end_headers()

            self.wfile.write(body)

            return

        if self.path.startswith("/device/"):

            device_id = self.path.split(
                "/device/",
                1,
            )[1]

            state = load_state()

            devices = state.get(
                "network_devices",
                [],
            )

            device = next(
                (
                    item
                    for item in devices
                    if isinstance(item, dict)
                    and str(
                        item.get(
                            "device_id",
                            "",
                        )
                    ) == device_id
                ),
                None,
            )

            if device is None:

                self.send_response(404)
                self.send_header(
                    "Content-Type",
                    "text/html; charset=utf-8",
                )
                self.end_headers()

                self.wfile.write(
                    b"<h1>NEXUS: Device Not Found</h1>"
                )

                return

            device_type = esc(
                device.get(
                    "device_type",
                    "UNKNOWN",
                )
            )

            vendor = esc(
                device.get(
                    "vendor",
                    "Unknown",
                )
            )

            ip = esc(
                device.get(
                    "ip",
                    "Unknown",
                )
            )

            port = esc(
                device.get(
                    "port",
                    "Unknown",
                )
            )

            vlan = esc(
                device.get(
                    "vlan",
                    "Unknown",
                )
            )

            observations = esc(
                device.get(
                    "observations",
                    0,
                )
            )

            html_page = f"""<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NEXUS Device</title>

<style>
body {{
    margin: 0;
    background: #080b10;
    color: #f5f7fa;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}}

main {{
    width: min(100% - 20px, 700px);
    margin: auto;
    padding: 20px 0 40px;
}}

a {{
    color: #58a6ff;
    text-decoration: none;
}}

.card {{
    margin-top: 16px;
    background: #11161d;
    border: 1px solid #222b35;
    border-radius: 14px;
    padding: 18px;
}}

.label {{
    color: #7f8a96;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: .12em;
    text-transform: uppercase;
    margin-top: 14px;
}}

.value {{
    margin-top: 5px;
    font-size: 20px;
}}

h1 {{
    margin-bottom: 0;
}}
</style>
</head>

<body>
<main>

<a href="/">← NEXUS Dashboard</a>

<h1>{device_type}</h1>

<div class="card">

<div class="label">Device ID</div>
<div class="value">{esc(device_id)}</div>

<div class="label">Vendor</div>
<div class="value">{vendor}</div>

<div class="label">IP Address</div>
<div class="value">{ip}</div>

<div class="label">Switch Port</div>
<div class="value">{port}</div>

<div class="label">VLAN</div>
<div class="value">{vlan}</div>

<div class="label">Observations</div>
<div class="value">{observations}</div>

</div>

</main>
</body>
</html>
"""

            body = html_page.encode()

            self.send_response(200)

            self.send_header(
                "Content-Type",
                "text/html; charset=utf-8",
            )

            self.send_header(
                "Content-Length",
                str(len(body)),
            )

            self.end_headers()

            self.wfile.write(body)

            return

        if self.path == "/api/state":

            body = json.dumps(
                load_state(),
                indent=2,
            ).encode()

            self.send_response(200)

            self.send_header(
                "Content-Type",
                "application/json",
            )

            self.send_header(
                "Content-Length",
                str(len(body)),
            )

            self.end_headers()

            self.wfile.write(body)

            return

        if self.path.startswith("/api/device/"):

            device_id = self.path.split(
                "/api/device/",
                1,
            )[1]

            state = load_state()

            devices = state.get(
                "network_devices",
                [],
            )

            if not isinstance(
                devices,
                list,
            ):
                devices = []

            device = next(
                (
                    item
                    for item in devices
                    if isinstance(item, dict)
                    and str(
                        item.get(
                            "device_id",
                            "",
                        )
                    ) == device_id
                ),
                None,
            )

            if device is None:

                body = json.dumps(
                    {
                        "error": "device_not_found",
                        "device_id": device_id,
                    },
                    indent=2,
                ).encode()

                self.send_response(404)

            else:

                body = json.dumps(
                    device,
                    indent=2,
                ).encode()

                self.send_response(200)

            self.send_header(
                "Content-Type",
                "application/json",
            )

            self.send_header(
                "Content-Length",
                str(len(body)),
            )

            self.end_headers()

            self.wfile.write(body)

            return

        if self.path != "/":

            self.send_response(404)
            self.end_headers()

            return

        state = load_state()
        ai_data = load_ai_result()
        ai_trigger_state = load_ai_trigger_state()
        ai_validation_state = load_ai_validation_state()
        hardware_health = load_hardware_health()


        status = esc(
            state.get(
                "status",
                "UNKNOWN",
            )
        ).upper()

        ai_status = str(
            ai_data.get(
                "status",
                "UNAVAILABLE",
            )
        ).upper()

        last_signature = ai_trigger_state.get(
            "last_signature"
        )

        current_signature = ai_trigger_state.get(
            "current_signature"
        )

        validation_status = str(
            ai_validation_state.get(
                "status",
                "UNKNOWN",
            )
        ).upper()

        validation_attempted_at = ai_validation_state.get(
            "attempted_at"
        )

        ai_generated_raw = ai_data.get(
            "generated_at"
        )

        ai_display_status = None

        if validation_status == "REJECTED":
            try:
                validation_time = datetime.fromisoformat(
                    str(validation_attempted_at).replace(
                        "Z",
                        "+00:00",
                    )
                )
                ai_time = datetime.fromisoformat(
                    str(ai_generated_raw).replace(
                        "Z",
                        "+00:00",
                    )
                )

                if validation_time > ai_time:
                    ai_display_status = "REJECTED"
            except (TypeError, ValueError):
                ai_display_status = "REJECTED"

        if ai_display_status is None:
            if ai_status == "UNAVAILABLE":
                ai_display_status = "UNAVAILABLE"
            elif (
                current_signature
                and last_signature
                and current_signature != last_signature
            ):
                ai_display_status = "PENDING"
            elif (
                current_signature
                and last_signature
                and current_signature == last_signature
            ):
                ai_display_status = "AVAILABLE"
            else:
                ai_display_status = "UNKNOWN"

        ai_status = esc(
            ai_display_status
        ).upper()

        # Load AI confidence before calculating the status class.
        # ai_result is parsed again below for the remaining AI fields.
        _early_ai_result = ai_data.get(
            "result",
            {},
        )

        if not isinstance(
            _early_ai_result,
            dict,
        ):
            _early_ai_result = {}

        ai_confidence = esc(
            _early_ai_result.get(
                "confidence",
                "UNKNOWN",
            )
        )

        ai_status_class = (
            "high"
            if ai_display_status == "REJECTED"
            else severity_class(
                ai_confidence
            )
        )

        ai_model = esc(
            ai_data.get(
                "model",
                "UNKNOWN",
            )
        )

        ai_generated_at = esc(
            format_timestamp(
                ai_data.get(
                    "generated_at"
                )
            )
        )

        ai_source_at = esc(
            format_timestamp(
                ai_data.get(
                    "source_intelligence_at"
                )
            )
        )

        ai_result = ai_data.get(
            "result",
            {},
        )

        if not isinstance(
            ai_result,
            dict,
        ):
            ai_result = {}

        ai_interpretation = esc(
            ai_result.get(
                "interpretation",
                "No AI interpretation available.",
            )
        )

        ai_confidence = esc(
            ai_result.get(
                "confidence",
                "UNKNOWN",
            )
        ).upper()

        ai_evidence_status = esc(
            ai_result.get(
                "evidence_status",
                "UNKNOWN",
            )
        ).upper()

        ai_recommendation = esc(
            ai_result.get(
                "recommended_action",
                "No recommendation available.",
            )
        )

        ai_reasoning = esc(
            ai_result.get(
                "reasoning_summary",
                "No reasoning summary available.",
            )
        )

        ai_validation_error = esc(
            ai_validation_state.get(
                "error",
                "No validation error recorded.",
            )
        )

        ai_validation_attempted = esc(
            format_timestamp(
                ai_validation_state.get(
                    "attempted_at"
                )
            )
        )

        hardware_overall = esc(
            hardware_health.get(
                "overall",
                "UNKNOWN",
            )
        ).upper()

        hardware_oled = esc(
            hardware_health.get(
                "oled",
                "UNKNOWN",
            )
        ).upper()

        hardware_led = esc(
            hardware_health.get(
                "led",
                "UNKNOWN",
            )
        ).upper()

        hardware_audio = esc(
            hardware_health.get(
                "audio",
                "UNKNOWN",
            )
        ).upper()

        hardware_updated = esc(
            format_timestamp(
                hardware_health.get(
                    "updated_at"
                )
            )
        )

        hardware_error = esc(
            hardware_health.get(
                "error"
            )
        )

        if ai_display_status == "REJECTED":
            ai_panel_label = "LAST VALID AI RESULT"
            ai_validation_note = (
                '<div class="ai-rejection">'
                '<div class="ai-label">LATEST AI ATTEMPT</div>'
                '<div class="ai-value">REJECTED BY NEXUS VALIDATION</div>'
                f'<div class="ai-meta">{ai_validation_error}</div>'
                f'<div class="ai-meta">ATTEMPTED {ai_validation_attempted}</div>'
                '</div>'
            )
        else:
            ai_panel_label = "NEXUS AI"
            ai_validation_note = ""

        risk = esc(
            state.get(
                "risk",
                "UNKNOWN",
            )
        ).upper()

        severity = esc(
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

        actionable_events = int(
            state.get(
                "actionable_events",
                0,
            )
        )

        classification = esc(
            state.get(
                "classification",
                "NORMAL",
            )
        ).upper()

        devices = int(
            state.get(
                "devices",
                0,
            )
        )

        top_event = esc(
            state.get(
                "top_event",
                "NO DATA",
            )
        )

        network = state.get(
            "network",
            {},
        )

        if not isinstance(network, dict):
            network = {}

        switch = network.get(
            "switch",
            {},
        )

        if not isinstance(switch, dict):
            switch = {}

        gateway = network.get(
            "gateway",
            {},
        )

        if not isinstance(gateway, dict):
            gateway = {}

        ports = network.get(
            "ports",
            {},
        )

        if not isinstance(ports, dict):
            ports = {}

        devices_data = state.get(
            "network_devices",
            [],
        )

        if not isinstance(devices_data, list):
            devices_data = []

        events_data = state.get(
            "active_event_details",
            [],
        )

        if not isinstance(events_data, list):
            events_data = []

        device_rows = "".join(
            device_row(device)
            for device in devices_data
            if isinstance(device, dict)
        )

        if not device_rows:
            device_rows = (
                '<div class="muted">No tracked devices</div>'
            )

        event_rows = "".join(
            event_row(event, index)
            for index, event in enumerate(events_data)
            if isinstance(event, dict)
        )

        if not event_rows:
            event_rows = (
                '<div class="muted">No active events</div>'
            )

        css_class = severity_class(
            severity
        )

        actionable_class = (
            "actionable"
            if actionable_events > 0
            else "normal"
        )

        page = f"""<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="5">
<title>NEXUS Security Console</title>

<style>
:root {{
    color-scheme: dark;
}}

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    background: #080b10;
    color: #f5f7fa;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}}

main {{
    width: min(100% - 24px, 1500px);
    margin: 0 auto;
    padding: 24px 0 48px;
}}

.header {{
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    gap: 12px;
    margin-bottom: 18px;
}}

.brand {{
    font-size: clamp(36px, 10vw, 54px);
    font-weight: 800;
    letter-spacing: .08em;
}}

.subtitle {{
    color: #7f8a96;
    font-size: 13px;
}}

.badge {{
    padding: 7px 10px;
    border: 1px solid #26303a;
    border-radius: 999px;
    color: #aab4bf;
    font-size: 11px;
    white-space: nowrap;
}}

.grid {{
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
}}

.card {{
    background: #11161d;
    border: 1px solid #222b35;
    border-radius: 14px;
    padding: 15px;
}}

.label {{
    color: #7f8a96;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: .12em;
    text-transform: uppercase;
}}

.value {{
    margin-top: 6px;
    font-size: 25px;
    font-weight: 750;
}}

.normal {{
    color: #56d364;
}}

.info {{
    color: #58a6ff;
}}

.medium {{
    color: #e3b341;
}}

.high {{
    color: #f85149;
}}

.critical {{
    color: #ff7b72;
}}

.actionable {{
    color: #e3b341;
}}

.section {{
    margin-top: 10px;
}}

.console {{
    margin-top: 8px;
    color: #aab4bf;
    font-size: 13px;
    line-height: 1.55;
}}
.ai-card {{
    margin-top: 14px;
}}

.ai-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
}}

.ai-status {{
    font-size: 11px;
    font-weight: 800;
    letter-spacing: .08em;
}}

.ai-text {{
    margin-top: 10px;
    color: #d1d7de;
    font-size: 14px;
    line-height: 1.55;
}}

.ai-meta {{
    margin-top: 10px;
    color: #7f8a96;
    font-size: 11px;
    line-height: 1.5;
}}

.ai-recommendation {{
    margin-top: 14px;
    padding: 12px;
    background: #0d1218;
    border: 1px solid #26303a;
    border-radius: 10px;
}}

.ai-rejection {{
    margin-top: 14px;
    padding: 12px;
    background: #160d0d;
    border: 1px solid #4a2525;
    border-radius: 10px;
}}


.ai-label {{
    color: #7f8a96;
    font-size: 9px;
    font-weight: 800;
    letter-spacing: .1em;
}}

.ai-value {{
    margin-top: 4px;
    color: #d1d7de;
    font-size: 13px;
    line-height: 1.5;
}}
.network-grid {{
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 14px;
    margin-top: 12px;
}}

.network-block {{
    min-width: 0;
    padding: 13px;
    background: #0d1218;
    border: 1px solid #26303a;
    border-radius: 10px;
    text-align: center;
}}

.gateway-block,
.topology-block {{
    text-align: center;
}}

.network-block-wide {{
    grid-column: 1 / -1;
}}

.network-label,
.port-label {{
    color: #7f8a96;
    font-size: 10px;
    font-weight: 800;
    letter-spacing: .1em;
}}

.network-value {{
    margin-top: 5px;
    font-size: 18px;
    font-weight: 750;
    overflow-wrap: anywhere;
}}

.network-meta {{
    margin-top: 4px;
    color: #7f8a96;
    font-size: 12px;
    overflow-wrap: anywhere;
}}

.port-grid {{
    display: grid;
    grid-template-columns: repeat(2, minmax(110px, 1fr));
    justify-content: center;
    gap: 8px;
    margin-top: 10px;
    max-width: 320px;
    margin-left: auto;
    margin-right: auto;
}}

.port-stat {{
    min-width: 0;
    text-align: center;
    padding: 10px 4px;
    background: #11161d;
    border: 1px solid #222b35;
    border-radius: 8px;
}}

.port-stat:last-child {{
    grid-column: 1 / -1;
    width: 50%;
    justify-self: center;
}}


.port-value {{
    font-size: 20px;
    font-weight: 750;
}}

.port-label {{
    margin-top: 3px;
    font-size: 9px;
    line-height: 1.2;
    overflow-wrap: anywhere;
}}

.device-row,
.event-row {{
    padding: 10px 0;
    border-top: 1px solid #222b35;
}}

.device-row:first-child,
.event-row:first-child {{
    border-top: 0;
}}

.device-title {{
    font-size: 15px;
    font-weight: 700;
}}

.device-title span {{
    color: #7f8a96;
    font-weight: 500;
}}

.device-meta {{
    margin-top: 3px;
    color: #7f8a96;
    font-size: 12px;
}}

.device-link {{
    display: inline-block;
    margin-top: 8px;
    color: #58a6ff;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: .05em;
    text-decoration: none;
}}

.event-severity {{
    font-size: 11px;
    font-weight: 800;
    letter-spacing: .08em;
}}

.event-message {{
    margin-top: 3px;
    font-size: 14px;
    line-height: 1.4;
    overflow-wrap: anywhere;
}}

.muted {{
    color: #7f8a96;
    font-size: 13px;
}}

.footer {{
    margin-top: 14px;
    color: #5f6b77;
    font-size: 11px;
    text-align: center;
}}

@media (min-width: 700px) {{
    main {{
        width: min(100% - 48px, 1100px);
        padding-top: 32px;
    }}

    .grid {{
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 14px;
    }}

    .card {{
        padding: 18px;
    }}

    .value {{
        font-size: 28px;
    }}

    .network-grid {{
        grid-template-columns: 2fr 1fr;
    }}

    .network-block-wide {{
        grid-column: 1 / -1;
    }}

    .port-grid {{
        grid-template-columns: repeat(5, minmax(0, 1fr));
        max-width: none;
        margin-left: 0;
        margin-right: 0;
        gap: 10px;
    }}

    .port-stat:last-child {{
        grid-column: auto;
        width: auto;
        justify-self: stretch;
    }}

    .port-label {{
        font-size: 10px;
    }}

}}

@media (min-width: 1100px) {{
    main {{
        width: min(100% - 64px, 1500px);
    }}

    .grid {{
        grid-template-columns: repeat(6, minmax(0, 1fr));
        gap: 14px;
    }}

    .section {{
        margin-top: 14px;
    }}

    .network-grid {{
        gap: 16px;
    }}

    .network-block {{
        padding: 16px;
    }}

    .network-value {{
        font-size: 19px;
    }}

    .port-stat {{
        padding: 12px 8px;
    }}

}}

@media (max-width: 420px) {{
    .value {{
        font-size: 22px;
    }}

    .card {{
        padding: 13px;
    }}

    .network-grid {{
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 8px;
    }}

    .network-block {{
        width: 100%;
        justify-self: stretch;
    }}

    .gateway-block {{
        width: 100%;
        justify-self: stretch;
    }}

    .topology-block {{
        grid-column: 1 / -1;
        width: 50%;
        justify-self: center;
    }}
}}

</style>
</head>

<body>
<main>

<header class="header">
    <div>
        <div class="brand">NEXUS</div>
        <div class="subtitle">Network Security Console</div>
    </div>

    <div class="badge">LIVE · 5s</div>
</header>

<section class="grid">

    <article class="card">
        <div class="label">Status</div>
        <div class="value normal">{status}</div>
    </article>

    <article class="card">
        <div class="label">Risk</div>
        <div class="value {css_class}">{risk}</div>
    </article>

    <article class="card">
        <div class="label">Severity</div>
        <div class="value {css_class}">{severity}</div>
    </article>

    <article class="card">
        <div class="label">Devices</div>
        <div class="value">{devices}</div>
    </article>

    <article class="card">
        <div class="label">Active Events</div>
        <div class="value {css_class}">{active_events}</div>
    </article>

    <article class="card">
        <div class="label">Classification</div>
        <div class="value">{classification}</div>
    </article>

    <article class="card">
        <div class="label">Actionable Events</div>
        <div class="value {actionable_class}">{actionable_events}</div>
    </article>

    <article class="card">
        <div class="label">Topology Edges</div>
        <div class="value">{network.get("topology_edges", 0)}</div>
    </article>

</section>

<section class="card section">
    <h2>HARDWARE HEALTH</h2>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:14px;">
        <div>
            <div class="ai-label">OVERALL</div>
            <div class="ai-value">{hardware_overall}</div>
        </div>

        <div>
            <div class="ai-label">OLED</div>
            <div class="ai-value">{hardware_oled}</div>
        </div>

        <div>
            <div class="ai-label">LED</div>
            <div class="ai-value">{hardware_led}</div>
        </div>

        <div>
            <div class="ai-label">AUDIO</div>
            <div class="ai-value">{hardware_audio}</div>
        </div>
    </div>

    <div class="ai-meta">
        LAST HARDWARE UPDATE {hardware_updated}
    </div>

    {(
        f'<div class="ai-meta">HARDWARE ERROR: {hardware_error}</div>'
        if hardware_error
        and str(hardware_error).lower() not in {"none", "null", ""}
        else ""
    )}
</section>

<section class="card section network-card">
    <div class="label">Network</div>

    <div class="network-grid">

        <div class="network-block gateway-block">
            <div class="network-label">Switch</div>
            <div class="network-value">
                {esc(switch.get("model", "Unknown"))}
            </div>
            <div class="network-meta">
                {esc(switch.get("hostname", "Unknown"))}
                ·
                {esc(switch.get("management_ip", "Unknown"))}
            </div>
        </div>

        <div class="network-block">
            <div class="network-label">Gateway</div>
            <div class="network-value">
                {esc(gateway.get("ip", "Unknown"))}
            </div>
        </div>

        <div class="network-block network-block-wide">
            <div class="network-label">Ports</div>

            <div class="port-grid">

                <div class="port-stat">
                    <div class="port-value">
                        {ports.get("total", 0)}
                    </div>
                    <div class="port-label">TOTAL</div>
                </div>

                <div class="port-stat">
                    <div class="port-value">
                        {ports.get("direct_devices", 0)}
                    </div>
                    <div class="port-label">DIRECT</div>
                </div>

                <div class="port-stat">
                    <div class="port-value">
                        {ports.get("multi_mac", 0)}
                    </div>
                    <div class="port-label">MULTI-MAC</div>
                </div>

                <div class="port-stat">
                    <div class="port-value">
                        {ports.get("connected_unknown", 0)}
                    </div>
                    <div class="port-label">UNKNOWN</div>
                </div>

                <div class="port-stat">
                    <div class="port-value">
                        {ports.get("disconnected", 0)}
                    </div>
                    <div class="port-label">DISCONNECTED</div>
                </div>

            </div>
        </div>

        <div class="network-block topology-block">
            <div class="network-label">Topology</div>
            <div class="network-value">
                {network.get("topology_edges", 0)}
            </div>
            <div class="network-meta">EDGES</div>
        </div>

    </div>
</section>

<section class="card section ai-card">

    <div class="ai-header">
        <div class="label">{ai_panel_label}</div>
        <div class="ai-status {ai_status_class}">
            {ai_status}
        </div>
    </div>

    <div class="ai-meta">
        MODEL {ai_model}
        ·
        CONFIDENCE {ai_confidence}
        ·
        EVIDENCE {ai_evidence_status}
    </div>

    {ai_validation_note}

    <div class="ai-text">
        {ai_interpretation}
    </div>

    <div class="ai-recommendation">
        <div class="ai-label">RECOMMENDED ACTION</div>
        <div class="ai-value">
            {ai_recommendation}
        </div>
    </div>

    <div class="ai-meta">
        AI GENERATED {ai_generated_at}
        ·
        SOURCE INTELLIGENCE {ai_source_at}
    </div>

</section>

<section class="card section">
    <div class="label">Tracked Devices</div>
    <div>
        {device_rows}
    </div>
</section>

<section class="card section">
    <div class="label">Active Events</div>
    <div>
        {event_rows}
    </div>
</section>

<section class="card section">
    <div class="label">Latest Event</div>
    <div class="console">
        {top_event}
    </div>
</section>

<section class="card section">
    <a class="device-link" href="/events">
        VIEW EVENT HISTORY →
    </a>
</section>

<div class="footer">
    NEXUS · Private Tailscale Service
</div>

</main>
</body>
</html>
"""

        body = page.encode()

        self.send_response(200)

        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8",
        )

        self.send_header(
            "Content-Length",
            str(len(body)),
        )

        self.end_headers()

        self.wfile.write(body)

    def log_message(self, *args):
        return


if __name__ == "__main__":

    print(
        f"NEXUS DASHBOARD listening on http://{HOST}:{PORT}",
        flush=True,
    )

    ThreadingHTTPServer(
        (HOST, PORT),
        Handler,
    ).serve_forever()

#!/usr/bin/env python3

import json
from datetime import datetime, timezone
from pathlib import Path


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

JETSON_STATE = (
    NEXUS
    / "hardware"
    / "state.json"
)

INTELLIGENCE_DIR = (
    NEXUS
    / "monitoring"
    / "intelligence"
)

INTELLIGENCE_CURRENT = (
    INTELLIGENCE_DIR
    / "current.json"
)

INTELLIGENCE_HISTORY = (
    INTELLIGENCE_DIR
    / "history.jsonl"
)

def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def load_events(path):
    events = []

    if not path.exists():
        return events

    with open(path, "r") as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            try:
                events.append(
                    json.loads(line)
                )
            except json.JSONDecodeError:
                continue

    return events

def format_timestamp(timestamp):
    """
    Convert an ISO timestamp into a human-readable 12-hour time.
    """
    if not timestamp:
        return "UNKNOWN"

    try:
        parsed = datetime.fromisoformat(timestamp)

        return parsed.strftime(
            "%B %d, %Y at %I:%M:%S %p"
        )

    except ValueError:
        return timestamp

def load_intelligence_history():
    """
    Load previous NEXUS intelligence snapshots.
    """

    history = []

    if not INTELLIGENCE_HISTORY.exists():
        return history

    with INTELLIGENCE_HISTORY.open(
        "r"
    ) as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            try:
                history.append(
                    json.loads(line)
                )
            except json.JSONDecodeError:
                continue

    return history

def build_intelligence_context():

    event_state = load_json(
        EVENT_STATE
    )

    jetson_state = load_json(
        JETSON_STATE
    )

    events = load_events(
        EVENT_LOG
    )

    context = {
        "intelligence_generated_at": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),
        "active_events": event_state.get(
            "active_events",
            [],
        ),

        "resolved_events": event_state.get(
            "resolved_events",
            [],
        ),

        "last_timestamp": event_state.get(
            "last_timestamp",
        ),

        "recent_events": events[-20:],

        "network": jetson_state.get(
            "network",
            {},
        ),

        "network_devices": jetson_state.get(
            "network_devices",
            [],
        ),

        "intelligence_history":
            load_intelligence_history(),

    }

    return context


def assess_event(event, context):

    severity = event.get(
        "severity",
        "INFO",
    )

    score = event.get(
        "score",
        0,
    )

    message = event.get(
        "message",
        "",
    )

    assessment = "NORMAL"

    confidence = "MEDIUM"

    reasons = []

    if severity == "CRITICAL":
        assessment = "HIGHLY_SUSPICIOUS"
        confidence = "HIGH"

        reasons.append(
            "The monitoring engine classified "
            "the event as CRITICAL."
        )

    elif severity == "HIGH":
        assessment = "SUSPICIOUS"
        confidence = "HIGH"

        reasons.append(
            "The monitoring engine classified "
            "the event as HIGH severity."
        )

    elif severity == "MEDIUM":
        assessment = "REVIEW"
        confidence = "MEDIUM"

        reasons.append(
            "The event represents a meaningful "
            "network change requiring context."
        )

    else:
        reasons.append(
            "The event is informational and "
            "does not currently indicate a "
            "high-risk condition."
        )

    if "New network device detected" in message:

        assessment = "REVIEW"

        reasons.append(
            "A previously unseen network identity "
            "was observed."
        )

    if "MAC identity changed" in message:

        assessment = "SUSPICIOUS"

        reasons.append(
            "A known device changed its observed "
            "network identity."
        )

    if "Device moved" in message:

        assessment = "SUSPICIOUS"

        reasons.append(
            "A known device was observed on a "
            "different switch port."
        )

    if "MAC added" in message:

        reasons.append(
            "An additional MAC address was "
            "associated with an existing device."
        )

    if "MAC removed" in message:

        reasons.append(
            "A previously observed MAC address "
            "is no longer associated with the device."
        )

    if "Topology port became inactive" in message:

        reasons.append(
            "A previously connected topology "
            "port became inactive."
        )

    return {
        "assessment": assessment,
        "confidence": confidence,
        "severity": severity,
        "score": score,
        "message": message,
        "reasons": reasons,
    }

def extract_subject(message):
    """
    Identify the primary device or port involved
    in a network event.
    """

    if "device " in message:
        start = message.find("device ") + len("device ")

        end = message.find(":", start)

        if end == -1:
            end = message.find(" ", start)

        if end != -1:
            return message[start:end]

    if "device " in message.lower():
        parts = message.split()

        for index, part in enumerate(parts):

            if part.lower() == "device":
                if index + 1 < len(parts):
                    return (
                        parts[index + 1]
                        .rstrip(":")
                    )

    if "Topology port became inactive:" in message:

        marker = "Topology port became inactive:"
        start = message.find(marker)

        if start != -1:
            subject = message[
                start + len(marker):
            ]

            if "|" in subject:
                subject = subject.split(
                    "|",
                    1,
                )[0]

            return subject.strip()

    if "on port:" in message:

        marker = "on port:"
        start = message.find(marker)

        if start != -1:

            subject = message[
                start + len(marker):
            ].strip()

            if subject.startswith(
                "ports."
            ):
                subject = subject[
                    len("ports.") :
                ]

            if "|" in subject:
                subject = subject.split(
                    "|",
                    1,
                )[0]

            return subject.strip()

    if "on " in message:

        marker = "on "
        start = message.find(marker)

        if start != -1:

            subject = message[
                start + len(marker):
            ]

            if ":" in subject:
                subject = subject.split(
                    ":",
                    1,
                )[0]

            if "|" in subject:
                subject = subject.split(
                    "|",
                    1,
                )[0]

            return subject.strip()

    return "network"


def correlate_events(events):
    """
    Group related events by their primary
    device or network object.
    """

    groups = {}

    for event in events:

        message = event.get(
            "message",
            "",
        )

        subject = extract_subject(
            message
        )

        if subject not in groups:
            groups[subject] = []

        groups[subject].append(
            event
        )

    return groups

def assess_situation(
    subject_type,
    subject,
    events,
    device_context,
):
    """
    Evaluate a group of correlated events as one
    network situation.
    """

    messages = [
        event.get(
            "message",
            "",
        )
        for event in events
    ]

    mac_added = sum(
        "MAC added to device " in message
        for message in messages
    )

    mac_removed = sum(
        "MAC removed from device " in message
        for message in messages
    )

    identity_changes = sum(
        "MAC identity changed on " in message
        for message in messages
    )

    port_changes = sum(
        (
            "Device moved:" in message
            or "Topology port" in message
        )
        for message in messages
    )

    highest_score = max(
        event.get(
            "score",
            0,
        )
        for event in events
    )

    assessment = "NORMAL ACTIVITY"
    risk = "NORMAL"
    confidence = "HIGH"

    explanation = (
        "Observed activity does not currently "
        "indicate unusual behavior."
    )

    investigation = (
        "No immediate investigation required."
    )

    if subject_type == "DEVICE":

        if (
            mac_added >= 2
            and mac_removed >= 2
        ):

            assessment = (
                "UNUSUAL NETWORK IDENTITY CHURN"
            )

            risk = "REVIEW"
            confidence = "MEDIUM"

            explanation = (
                "Multiple MAC addresses were added "
                "and removed from the same device "
                "within the correlation window."
            )

            investigation = (
                "Review MAC history, ARP correlation, "
                "and whether the device remained on "
                "the same switch port."
            )

        elif identity_changes > 0:

            assessment = (
                "NETWORK IDENTITY CHANGE"
            )

            risk = "REVIEW"
            confidence = "MEDIUM"

            explanation = (
                "The device changed its observed "
                "MAC identity."
            )

            investigation = (
                "Review the previous and current "
                "MAC identities and verify the "
                "device's switch port."
            )

        elif (
            mac_added > 0
            or mac_removed > 0
        ):

            assessment = (
                "NETWORK IDENTITY CHANGE"
            )

            risk = "REVIEW"
            confidence = "LOW"

            explanation = (
                "A MAC address was added or removed "
                "from the device."
            )

            investigation = (
                "Monitor for repeated changes or "
                "simultaneous port and IP changes."
            )

        elif highest_score >= 25:

            assessment = (
                "SIGNIFICANT DEVICE ACTIVITY"
            )

            risk = "REVIEW"
            confidence = "HIGH"

            explanation = (
                "The device has a high-scored event "
                "associated with it."
            )

            investigation = (
                "Review the device event history and "
                "its current network location."
            )

    elif subject_type == "PORT":

        if any(
            "Topology port became inactive:" in message
            for message in messages
        ):

            assessment = (
                "DEVICE DISCONNECTED"
            )

            risk = "REVIEW"
            confidence = "HIGH"

            explanation = (
                "A previously active topology port "
                "became inactive."
            )

            investigation = (
                "Determine whether the connected "
                "device was intentionally disconnected."
            )

        elif highest_score >= 15:

            assessment = (
                "PORT ANOMALY"
            )

            risk = "REVIEW"
            confidence = "MEDIUM"

            explanation = (
                "The port is associated with a "
                "security-scored topology event."
            )

            investigation = (
                "Identify the connected device and "
                "review recent MAC and topology changes."
            )

    elif subject_type == "NETWORK":

        if highest_score == 0:

            assessment = (
                "NETWORK HEALTH CHANGE"
            )

            risk = "NORMAL"
            confidence = "HIGH"

            explanation = (
                "Network health metrics changed "
                "without an associated security-scored "
                "event."
            )

            investigation = (
                "No immediate action required."
            )

        elif highest_score >= 15:

            assessment = (
                "NETWORK ANOMALY"
            )

            risk = "REVIEW"
            confidence = "MEDIUM"

            explanation = (
                "The network correlation contains "
                "a security-scored event requiring review."
            )

            investigation = (
                "Review the contributing event and "
                "identify the affected device or port."
            )

    return {
        "assessment": assessment,
        "risk": risk,
        "confidence": confidence,
        "explanation": explanation,
        "investigation": investigation,
        "metrics": {
            "mac_added": mac_added,
            "mac_removed": mac_removed,
            "identity_changes": identity_changes,
            "port_changes": port_changes,
        },
    }

def find_related_devices(
    subject,
    subject_type,
    network_devices,
    messages,
):
    """
    Find network devices related to a situation.
    """

    related = []

    for device in network_devices:

        device_id = device.get(
            "device_id",
            ""
        )

        port = device.get(
            "port",
            ""
        )

        matched = False

        if subject_type == "DEVICE":

            matched = (
                device_id == subject
            )

        elif subject_type == "PORT":

            matched = (
                port == subject
            )

        elif subject_type == "NETWORK":

            matched = any(
                device_id in message
                or port in message
                for message in messages
            )

        if matched:
            related.append(device)

    return related

def analyze_historical_pattern(
    subject,
    subject_type,
    history,
    current_situation,
    current_timestamp,
):
    """
    Analyze persistence and recurrence of a situation
    across previous NEXUS intelligence snapshots.
    """

    snapshot_states = []

    for snapshot in history:

        snapshot_timestamp = snapshot.get(
            "generated_at"
        )

        matching_situation = None

        for situation in snapshot.get(
            "situations",
            [],
        ):

            if (
                situation.get("subject") == subject
                and situation.get("subject_type")
                == subject_type
            ):
                matching_situation = situation
                break

        is_meaningful = (
            matching_situation is not None
            and matching_situation.get(
                "assessment",
                "NORMAL ACTIVITY",
            )
            != "NORMAL ACTIVITY"
        )

        snapshot_states.append(
            {
                "timestamp": snapshot_timestamp,
                "meaningful": is_meaningful,
            }
        )

    observations = sum(
        state["meaningful"]
        for state in snapshot_states
    )

    recurrences = 0
    was_meaningful = False

    for state in snapshot_states:

        is_meaningful = state[
            "meaningful"
        ]

        if (
            is_meaningful
            and not was_meaningful
        ):
            recurrences += 1

        was_meaningful = is_meaningful

    current_is_meaningful = (
        current_situation != "NORMAL ACTIVITY"
    )

    first_observed_at = None
    last_observed_at = None

    for state in snapshot_states:

        if state["meaningful"]:

            if first_observed_at is None:
                first_observed_at = (
                    state["timestamp"]
                )

            last_observed_at = (
                state["timestamp"]
            )

    persistence_observations = 0

    if current_is_meaningful:

        for state in reversed(
            snapshot_states
        ):

            if not state["meaningful"]:
                break

            persistence_observations += 1

        persistence_observations += 1

        if first_observed_at is None:
            first_observed_at = (
                current_timestamp
            )

        last_observed_at = (
            current_timestamp
        )

    return {
        "observations": observations,
        "recurrences": recurrences,
        "recurring": recurrences >= 2,
        "currently_persistent": (
            current_is_meaningful
        ),
        "first_observed_at": (
            first_observed_at
        ),
        "last_observed_at": (
            last_observed_at
        ),
        "persistence_observations": (
            persistence_observations
        ),
    }

def build_situations(context):
    """
    Convert individual events into correlated
    network situations.
    """

    recent_events = context.get(
        "recent_events",
        [],
    )

    groups = correlate_events(
        recent_events
    )

    situations = []

    for subject, events in groups.items():

        if not events:
            continue

        highest_score = max(
            event.get(
                "score",
                0,
            )
            for event in events
        )

        severities = {
            event.get(
                "severity",
                "INFO",
            )
            for event in events
        }

        messages = [
            event.get(
                "message",
                "",
            )
            for event in events
        ]

        if subject.startswith("Fa"):

            subject_type = "PORT"

        elif subject == "network":

            subject_type = "NETWORK"

        else:

            subject_type = "DEVICE"

        related_devices = find_related_devices(
            subject,
            subject_type,
            context.get(
                "network_devices",
                [],
            ),
            messages,
        )


        assessment_result = assess_situation(
            subject_type,
            subject,
            events,
            context.get(
                "network_devices",
                {},
            ),
        )

        assessment = assessment_result[
            "assessment"
        ]

        historical_pattern = (
            analyze_historical_pattern(
                subject,
                subject_type,
                context.get(
                    "intelligence_history",
                    [],
                ),
                assessment,
                context.get(
                    "intelligence_generated_at"
                ),
            )
        )

        situations.append(
            {
                "subject": subject,
                "subject_type": subject_type,
                "observed_at": context.get(
                    "intelligence_generated_at"
                ),
                "event_count": len(events),
                "highest_score": highest_score,
                "severities": sorted(
                    severities
                ),
                "assessment": assessment,
                "risk": assessment_result[
                    "risk"
                ],
                "confidence": assessment_result[
                    "confidence"
                ],
                "explanation": assessment_result[
                    "explanation"
                ],
                "investigation": assessment_result[
                    "investigation"
                ],
                "metrics": assessment_result[
                    "metrics"
                ],
                "related_devices": related_devices,
                "historical_pattern":
                    historical_pattern,
                "events": messages,
            }
        )

    situations.sort(
        key=lambda situation: (
            situation["highest_score"],
            situation["event_count"],
        ),
        reverse=True,
    )

    return situations

def build_ai_context(
    context,
    situations,
):
    """
    Build a compact, structured context object
    for future AI interpretation.
    """

    ai_situations = []

    for situation in situations:

        related_devices = []

        for device in situation.get(
            "related_devices",
            [],
        ):

            related_devices.append(
                {
                    "device_id": device.get(
                        "device_id"
                    ),
                    "device_type": device.get(
                        "device_type"
                    ),
                    "vendor": device.get(
                        "vendor"
                    ),
                    "ip": device.get(
                        "ip"
                    ),
                    "port": device.get(
                        "port"
                    ),
                    "vlan": device.get(
                        "vlan"
                    ),
                }
            )

        ai_situations.append(
            {
                "subject": situation.get(
                    "subject"
                ),
                "subject_type": situation.get(
                    "subject_type"
                ),
                "assessment": situation.get(
                    "assessment"
                ),
                "risk": situation.get(
                    "risk"
                ),
                "confidence": situation.get(
                    "confidence"
                ),
                "event_count": situation.get(
                    "event_count",
                    0,
                ),
                "highest_score": situation.get(
                    "highest_score",
                    0,
                ),
                "metrics": situation.get(
                    "metrics",
                    {},
                ),
                "historical_pattern": situation.get(
                    "historical_pattern",
                    {},
                ),
                "related_devices": (
                    related_devices
                ),
            }
        )

    return {
        "timestamp": context.get(
            "intelligence_generated_at"
        ),
        "network": {
            "switch": context.get(
                "network",
                {}
            ).get(
                "switch",
                {}
            ),
            "gateway": context.get(
                "network",
                {}
            ).get(
                "gateway",
                {}
            ),
            "ports": context.get(
                "network",
                {}
            ).get(
                "ports",
                {}
            ),
        },
        "active_events": len(
            context.get(
                "active_events",
                [],
            )
        ),
        "network_devices": len(
            context.get(
                "network_devices",
                [],
            )
        ),
        "situations": ai_situations,
    }

def publish_intelligence(context, situations):
    """
    Publish the current structured NEXUS intelligence state.
    """

    INTELLIGENCE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    ai_context = build_ai_context(
        context,
        situations,
    )

    output = {
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "source_last_event_at": context.get(
            "last_timestamp"
        ),
        "active_events": len(
            context.get(
                "active_events",
                [],
            )
        ),
        "recent_events": len(
            context.get(
                "recent_events",
                [],
            )
        ),
        "network_devices": len(
            context.get(
                "network_devices",
                [],
            )
        ),
        "situation_count": len(
            situations
        ),
        "situations": situations,
        "ai_context": ai_context,
    }

    with INTELLIGENCE_CURRENT.open(
        "w"
    ) as file:
        json.dump(
            output,
            file,
            indent=2,
        )

    history_record = {
        "generated_at": output["generated_at"],
        "source_last_event_at": output[
            "source_last_event_at"
        ],
        "active_events": output[
            "active_events"
        ],
        "recent_events": output[
            "recent_events"
        ],
        "network_devices": output[
            "network_devices"
        ],
        "situation_count": output[
            "situation_count"
        ],
        "situations": output[
            "situations"
        ],
    }

    with INTELLIGENCE_HISTORY.open(
        "a"
    ) as file:
        file.write(
            json.dumps(
                history_record
            )
            + "\n"
        )

    return output

def main():

    context = build_intelligence_context()

    situations = build_situations(
        context
    )

    intelligence = publish_intelligence(
        context,
        situations,
    )

    print()

    print(
        "============ NEXUS INTELLIGENCE ============"
    )
    print()

    print(
        "Generated:",
        format_timestamp(
            intelligence["generated_at"]
        ),
    )

    print(
        "Latest event:",
        format_timestamp(
            intelligence["source_last_event_at"]
        ),
    )

    print()

    print(
        f"Active events: "
        f"{len(context['active_events'])}"
    )

    print(
        f"Recent events: "
        f"{len(context['recent_events'])}"
    )

    print(
        f"Network devices: "
        f"{len(context['network_devices'])}"
    )

    print(
        f"Correlated situations: "
        f"{len(situations)}"
    )

    print()

    for situation in situations:

        print(
            f"[{situation['assessment']}] "
            f"{situation['subject']} "
            f"events={situation['event_count']} "
            f"highest_score="
            f"{situation['highest_score']}"
        )

        print(
            "  Severities: "
            + ", ".join(
                situation["severities"]
            )
        )

        for message in situation[
            "events"
        ]:

            print(
                f"  → {message}"
            )

        print()


if __name__ == "__main__":
    main()

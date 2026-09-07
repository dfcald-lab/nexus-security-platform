#!/usr/bin/env python3

import argparse
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from datetime import datetime, timezone


NEXUS = Path.home() / "nexus"

INTELLIGENCE_DIR = (
    NEXUS
    / "monitoring"
    / "intelligence"
)

INTELLIGENCE_CURRENT = (
    INTELLIGENCE_DIR
    / "current.json"
)

HTB_SESSION_DIR = (
    NEXUS
    / "operator"
    / "htb_sessions"
)

OLLAMA_URL = (
    "http://127.0.0.1:11434/api/chat"
)

MODEL = "qwen3:1.7b"


BLOCKED_UNSUPPORTED_TERMS = (
    "unauthorized access",
    "unauthorized user",
    "malicious",
    "malware",
    "compromised",
    "intrusion",
    "attacker",
    "attack occurred",
    "impersonating",
    "spoofing",
)


def load_json(path, default=None):

    if default is None:
        default = {}

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as file:
            return json.load(file)

    except (
        OSError,
        json.JSONDecodeError,
    ):
        return default


def call_ollama(prompt):

    parsed = urllib.parse.urlparse(
        OLLAMA_URL
    )

    allowed_hosts = {
        "127.0.0.1",
        "localhost",
        "::1",
    }

    if (
        parsed.scheme != "http"
        or parsed.hostname not in allowed_hosts
        or parsed.port != 11434
        or parsed.path != "/api/chat"
    ):
        raise RuntimeError(
            "NEXUS Operator refused a non-local Ollama endpoint: "
            + OLLAMA_URL
        )

    payload = {
        "model": MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are the NEXUS Operator AI. "
                    "You are a local advisory security assistant. "
                    "The human operator remains in control. "
                    "Never claim you executed a command or changed "
                    "a system. "
                    "Use only supplied evidence. "
                    "Never invent facts. "
                    "Always distinguish OBSERVED, POSSIBLE, and "
                    "UNDETERMINED information. "
                    "Do not infer maliciousness, authorization, "
                    "compromise, spoofing, intrusion, attacker intent, "
                    "or identity from MAC churn alone. "
                    "Do not turn descriptive labels into facts."
                ),
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        "stream": False,
        "think": False,
        "options": {
            "temperature": 0,
        },
    }

    request = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(
            payload
        ).encode("utf-8"),
        headers={
            "Content-Type": "application/json"
        },
        method="POST",
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=120,
        ) as response:

            raw = response.read().decode(
                "utf-8"
            )

        response_data = json.loads(
            raw
        )

        message = response_data.get(
            "message",
            {},
        )

        content = message.get(
            "content",
            "",
        )

        if not content:
            raise RuntimeError(
                "Ollama returned an empty response."
            )

        return content.strip()

    except urllib.error.URLError as error:

        raise RuntimeError(
            f"Could not connect to local Ollama: {error}"
        ) from error


def validate_analyst_response(response):

    lowered = response.lower()

    authorization_terms = {
        "unauthorized access",
        "unauthorized user",
    }

    security_attribution_terms = {
        "malicious",
        "malware",
        "compromised",
        "intrusion",
        "attacker",
        "attack occurred",
        "impersonating",
        "spoofing",
    }

    if any(
        term in lowered
        for term in authorization_terms
    ):

        return (
            False,
            "authorization_claim",
        )

    if any(
        term in lowered
        for term in security_attribution_terms
    ):

        return (
            False,
            "unsupported_security_attribution",
        )

    required_markers = (
        "observed",
        "possible",
        "undetermined",
    )

    marker_count = sum(
        marker in lowered
        for marker in required_markers
    )

    if marker_count == 0:

        return (
            False,
            "missing_evidence_sections",
        )

    return (
        True,
        None,
    )


def load_current_intelligence():

    intelligence = load_json(
        INTELLIGENCE_CURRENT,
        {},
    )

    if not intelligence:
        raise RuntimeError(
            "No current NEXUS intelligence is available."
        )

    return intelligence


def analyst_prompt(
    question,
    intelligence,
):

    return f"""
You are operating in NEXUS ANALYST mode.

Answer the operator's question using ONLY the supplied
NEXUS intelligence.

REQUIRED RESPONSE STRUCTURE:

OBSERVED FACTS:
Only facts directly present in the supplied evidence.

POSSIBLE EXPLANATIONS:
Plausible interpretations clearly labeled as hypotheses.

UNDETERMINED:
Explain what the evidence does not establish.

RECOMMENDED INVESTIGATION:
Give neutral, operator-controlled investigation steps.

STRICT RULES:

- Never invent devices, IPs, ports, vendors, identities,
  users, causes, vulnerabilities, or actions.
- Do not call activity malicious unless the evidence directly
  establishes that conclusion.
- Do not call activity unauthorized unless the evidence directly
  establishes authorization status.
- Do not infer identity changes from MAC additions/removals.
- Do not infer port movement when port_changes is zero.
- Do not infer compromise from unusual activity alone.
- Do not describe an observed MAC address as a confirmed user,
  device, or attacker identity.
- Do not claim commands were executed.
- Deterministic NEXUS metrics are authoritative.
- Zero-valued metrics are observations, not missing data.

OPERATOR QUESTION:
{question}

CURRENT NEXUS INTELLIGENCE:
{json.dumps(intelligence, indent=2)}
""".strip()



def build_deterministic_analyst_response(
    question,
    intelligence,
):
    situations = intelligence.get(
        "situations",
        [],
    )

    if not isinstance(situations, list):
        situations = []

    active_events = intelligence.get(
        "active_events",
        0,
    )

    try:
        active_event_count = int(
            active_events
        )
    except (TypeError, ValueError):
        active_event_count = 0

    recent_events = intelligence.get(
        "recent_events",
        0,
    )

    try:
        recent_event_count = int(
            recent_events
        )
    except (TypeError, ValueError):
        recent_event_count = 0

    # --------------------------------------------------------
    # Determine whether the operator is asking about the
    # current state or a broader historical/recent picture.
    # --------------------------------------------------------

    question_lower = str(
        question
    ).lower()

    current_words = (
        "current",
        "right now",
        "active",
        "currently",
        "present",
        "now",
    )

    asks_current = any(
        word in question_lower
        for word in current_words
    )

    # NEXUS intelligence contains situation-level information,
    # while active_events is a raw-event count. A situation is
    # considered current when at least one of its underlying
    # event messages appears in the active-event evidence.
    raw_active_events = intelligence.get(
        "active_event_details",
        [],
    )

    if not isinstance(
        raw_active_events,
        list,
    ):
        raw_active_events = []

    active_messages = set()

    for event in raw_active_events:

        if not isinstance(event, dict):
            continue

        message = event.get(
            "message"
        )

        if message:
            active_messages.add(
                str(message)
            )

    active_situations = []

    for situation in situations:

        if not isinstance(
            situation,
            dict,
        ):
            continue

        situation_events = situation.get(
            "events",
            [],
        )

        if not isinstance(
            situation_events,
            list,
        ):
            situation_events = []

        if any(
            str(event) in active_messages
            for event in situation_events
        ):
            active_situations.append(
                situation
            )

    if asks_current:

        if active_situations:

            ranked = sorted(
                active_situations,
                key=lambda situation: (
                    situation.get(
                        "highest_score",
                        0,
                    ),
                    situation.get(
                        "event_count",
                        0,
                    ),
                ),
                reverse=True,
            )

            selection_label = "CURRENT ACTIVE"

        else:

            return (
                "OBSERVED FACTS:\n"
                "- NEXUS currently reports "
                f"{active_event_count} active event(s).\n"
                "- No correlated situation is currently "
                "identified as active.\n"
                f"- NEXUS has {recent_event_count} recent "
                "event(s) in its intelligence window.\n\n"
                "POSSIBLE EXPLANATIONS:\n"
                "- Recent situations may reflect historical "
                "activity rather than a current incident.\n\n"
                "UNDETERMINED:\n"
                "- The supplied evidence does not establish "
                "a current security incident.\n\n"
                "RECENT / HISTORICAL CONTEXT:\n"
                + (
                    "\n".join(
                        [
                            "- "
                            + str(
                                situation.get(
                                    "subject",
                                    "UNKNOWN",
                                )
                            )
                            + ": "
                            + str(
                                situation.get(
                                    "assessment",
                                    "UNKNOWN",
                                )
                            )
                            + " (risk="
                            + str(
                                situation.get(
                                    "risk",
                                    "UNKNOWN",
                                )
                            )
                            + ", score="
                            + str(
                                situation.get(
                                    "highest_score",
                                    0,
                                )
                            )
                            + ")"
                            for situation in sorted(
                                situations,
                                key=lambda situation: (
                                    situation.get(
                                        "highest_score",
                                        0,
                                    ),
                                    situation.get(
                                        "event_count",
                                        0,
                                    ),
                                ),
                                reverse=True,
                            )[:3]
                        ]
                    )
                    if situations
                    else "- No recent correlated situations."
                )
                + "\n\n"
                "RECOMMENDED INVESTIGATION:\n"
                "- Continue monitoring for a new active "
                "incident.\n"
                "- Review recent situations separately "
                "from the current active state."
            )

    elif active_situations and active_event_count > 0:

        ranked = sorted(
            active_situations,
            key=lambda situation: (
                situation.get(
                    "highest_score",
                    0,
                ),
                situation.get(
                    "event_count",
                    0,
                ),
            ),
            reverse=True,
        )

        selection_label = "CURRENT ACTIVE"

    elif situations:

        ranked = sorted(
            situations,
            key=lambda situation: (
                situation.get(
                    "highest_score",
                    0,
                ),
                situation.get(
                    "event_count",
                    0,
                ),
            ),
            reverse=True,
        )

        selection_label = "RECENT / HISTORICAL"

    else:

        return (
            "OBSERVED FACTS:\n"
            "- NEXUS currently has no correlated situations "
            "to analyze.\n"
            f"- Active event count: {active_event_count}.\n"
            f"- Recent event count: {recent_event_count}.\n\n"
            "POSSIBLE EXPLANATIONS:\n"
            "- No supported explanation is available from "
            "the supplied intelligence.\n\n"
            "UNDETERMINED:\n"
            "- The supplied evidence does not establish "
            "a current security condition.\n\n"
            "RECOMMENDED INVESTIGATION:\n"
            "- Continue monitoring for new events."
        )

    top = ranked[0]

    subject = top.get(
        "subject",
        "UNKNOWN",
    )

    assessment = top.get(
        "assessment",
        "UNKNOWN",
    )

    risk = top.get(
        "risk",
        "UNKNOWN",
    )

    confidence = top.get(
        "confidence",
        "UNKNOWN",
    )

    event_count = top.get(
        "event_count",
        0,
    )

    highest_score = top.get(
        "highest_score",
        0,
    )

    metrics = top.get(
        "metrics",
        {},
    )

    related_devices = top.get(
        "related_devices",
        [],
    )

    events = top.get(
        "events",
        [],
    )

    observed = []

    observed.append(
        f"- NEXUS selection: {selection_label}."
    )

    observed.append(
        f"- Highest-ranked situation: {subject}."
    )

    observed.append(
        f"- NEXUS assessment: {assessment}."
    )

    observed.append(
        f"- Risk: {risk}; confidence: {confidence}."
    )

    observed.append(
        f"- Correlated event count for this situation: "
        f"{event_count}."
    )

    observed.append(
        f"- Highest event score: {highest_score}."
    )

    observed.append(
        f"- NEXUS active event count: "
        f"{active_event_count}."
    )

    observed.append(
        f"- NEXUS recent event count: "
        f"{recent_event_count}."
    )

    if isinstance(
        metrics,
        dict,
    ) and metrics:

        observed.append(
            "- Structured metrics supplied by NEXUS:"
        )

        for key, value in metrics.items():

            observed.append(
                f"  - {key}: {json.dumps(value)}"
            )

    if related_devices:

        observed.append(
            "- Related devices identified by NEXUS:"
        )

        for device in related_devices:

            observed.append(
                "  - "
                + json.dumps(
                    device,
                    sort_keys=True,
                )
            )

    historical = top.get(
        "historical_pattern",
        {},
    )

    historical_summary = (
        historical.get(
            "summary"
        )
        if isinstance(
            historical,
            dict,
        )
        else None
    )

    if historical_summary:

        possible_lines = [
            "- Historical context reported by NEXUS: "
            f"{historical_summary}.",
            "- This historical context does not by itself "
            "establish the cause of the current activity.",
        ]

    else:

        possible_lines = [
            "- The supplied evidence does not establish "
            "a specific cause."
        ]

    undetermined_lines = [
        "- The supplied evidence does not establish "
        "authorization status, attacker intent, compromise, "
        "or a specific root cause.",
        "- A stronger security conclusion requires additional "
        "validation beyond the supplied evidence.",
    ]

    investigation = [
        "- Investigate the selected situation first.",
        "- Compare its current metrics with subsequent "
        "monitoring cycles.",
        "- Review the underlying events listed by NEXUS.",
    ]

    investigation_text = top.get(
        "investigation",
    )

    if investigation_text:

        investigation.insert(
            1,
            "- NEXUS recommends: "
            + str(
                investigation_text
            ),
        )

    if events:

        investigation.append(
            "- Underlying evidence includes:"
        )

        for event in events[:5]:

            investigation.append(
                f"  - {event}"
            )

    return (
        "OBSERVED FACTS:\n"
        + "\n".join(
            observed
        )
        + "\n\n"
        + "POSSIBLE EXPLANATIONS:\n"
        + "\n".join(
            possible_lines
        )
        + "\n\n"
        + "UNDETERMINED:\n"
        + "\n".join(
            undetermined_lines
        )
        + "\n\n"
        + "RECOMMENDED INVESTIGATION:\n"
        + "\n".join(
            investigation
        )
    )



def load_htb_session(
    name,
):

    path = HTB_SESSION_DIR / f"{name}.json"

    try:

        with path.open(
            "r",
            encoding="utf-8",
        ) as file:

            session = json.load(
                file
            )

    except FileNotFoundError:

        raise RuntimeError(
            f"HTB session not found: {name}"
        )

    except (
        OSError,
        json.JSONDecodeError,
    ) as error:

        raise RuntimeError(
            f"Could not read HTB session {name}: {error}"
        ) from error

    if not isinstance(
        session,
        dict,
    ):

        raise RuntimeError(
            f"HTB session {name} is invalid."
        )

    return session


def htb_session_context(
    session,
):

    return json.dumps(
        {
            "session": session.get(
                "name",
                "UNKNOWN",
            ),
            "target": session.get(
                "target",
                "",
            ),
            "findings": session.get(
                "findings",
                [],
            ),
            "notes": session.get(
                "notes",
                [],
            ),
        },
        indent=2,
    )


def htb_prompt(
    session,
    operator_input,
):

    session_data = htb_session_context(
        session
    )

    return f"""
You are NEXUS HTB, an interactive penetration-testing
study and troubleshooting assistant.

The human operator is working on an authorized
Hack The Box target.

Use the complete saved session as context.

Your job is to help the operator:

- interpret reconnaissance
- understand services
- analyze web applications
- identify promising attack paths
- explain vulnerabilities
- troubleshoot failed commands or exploits
- reason about privilege escalation
- compare hypotheses
- identify missing evidence
- organize findings
- explain why a technique may or may not work
- create concise technical notes and write-up material

IMPORTANT:

The operator is the person executing commands.

Never claim that you executed a command.

Never invent scan results, credentials, ports,
software versions, vulnerabilities, users, or target
properties.

Treat supplied observations as evidence.

Clearly separate:
OBSERVED FACTS
POSSIBLE HYPOTHESES
MISSING / UNDETERMINED INFORMATION
NEXT INVESTIGATION STEPS

Keep recommendations tied to the supplied target
and the evidence already present in the session.

CURRENT SAVED SESSION:
{session_data}

NEW OPERATOR INPUT:
{operator_input}
""".strip()


def interactive_analyst():

    print()
    print(
        "============ NEXUS ANALYST ============"
    )
    print()
    print(
        "Ask about the current NEXUS state."
    )
    print(
        "Type 'exit' to leave."
    )
    print()

    while True:

        try:
            question = input(
                "nexus> "
            ).strip()

        except EOFError:
            break

        if not question:
            continue

        if question.lower() in {
            "exit",
            "quit",
        }:
            break

        intelligence = load_current_intelligence()

        response = call_ollama(
            analyst_prompt(
                question,
                intelligence,
            )
        )

        valid, error = validate_analyst_response(
            response
        )

        print()

        if not valid:

            print(
                "NEXUS Analyst AI response did not pass "
                "the evidence guard."
            )

            print(
                "Falling back to deterministic NEXUS analysis."
            )

            print()

            response = (
                build_deterministic_analyst_response(
                    question,
                    intelligence,
                )
            )

        print(
            response
        )

        print()


def interactive_htb(
    session_name,
):

    session = load_htb_session(
        session_name
    )

    print()
    print(
        "============ NEXUS HTB MODE ============"
    )
    print()

    print(
        "Session:",
        session.get(
            "name",
            session_name,
        ),
    )

    print(
        "Target:",
        session.get(
            "target",
        )
        or "Not set",
    )

    print()
    print(
        "Enter a question, finding, recon output, "
        "error, or hypothesis."
    )

    print(
        "The saved session is included with every "
        "AI request."
    )

    print(
        "Type 'exit' to leave."
    )

    print()

    while True:

        try:

            operator_input = input(
                "htb> "
            ).strip()

        except EOFError:
            break

        if not operator_input:
            continue

        if operator_input.lower() in {
            "exit",
            "quit",
        }:
            break

        response = call_ollama(
            htb_prompt(
                session,
                operator_input,
            )
        )

        print()
        print(
            response
        )
        print()

def main():

    parser = argparse.ArgumentParser(
        description="NEXUS Operator AI"
    )

    parser.add_argument(
        "mode",
        choices=[
            "analyst",
            "htb",
        ],
    )

    parser.add_argument(
        "--session",
        help=(
            "HTB session name. Required for HTB mode."
        ),
    )

    args = parser.parse_args()

    if args.mode == "analyst":

        interactive_analyst()

    elif args.mode == "htb":

        if not args.session:

            parser.error(
                "--session is required for HTB mode"
            )

        interactive_htb(
            args.session
        )


if __name__ == "__main__":
    main()

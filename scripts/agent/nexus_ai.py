#!/usr/bin/env python3

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


NEXUS = Path.home() / "nexus"

INTELLIGENCE_CURRENT = (
    NEXUS
    / "monitoring"
    / "intelligence"
    / "current.json"
)

AI_OUTPUT = (
    NEXUS
    / "monitoring"
    / "intelligence"
    / "ai_result.json"
)

AI_TRIGGER_STATE = (
    NEXUS
    / "monitoring"
    / "intelligence"
    / "ai_trigger_state.json"
)

AI_COOLDOWN_SECONDS = 300

OLLAMA_URL = (
    "http://127.0.0.1:11434/api/generate"
)

MODEL = "qwen3:1.7b"

AI_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "interpretation": {
            "type": "string"
        },
        "confidence": {
            "type": "string",
            "enum": [
                "LOW",
                "MEDIUM",
                "HIGH",
            ],
        },
        "recommended_action": {
            "type": "string"
        },
        "reasoning_summary": {
            "type": "string"
        },
        "evidence_status": {
            "type": "string",
            "enum": [
                "OBSERVED",
                "POSSIBLE",
                "UNDETERMINED",
            ],
        },
    },
    "required": [
        "interpretation",
        "confidence",
        "recommended_action",
        "reasoning_summary",
        "evidence_status",
    ],
    "additionalProperties": False,
}


def load_json(path):
    with path.open("r") as file:
        return json.load(file)

def load_trigger_state():
    default = {
        "last_run_at": None,
        "last_signature": None,
    }

    try:
        with AI_TRIGGER_STATE.open("r") as file:
            data = json.load(file)

        if isinstance(data, dict):
            default.update(data)

    except (
        OSError,
        json.JSONDecodeError,
    ):
        pass

    return default


def build_situation_signature(ai_context):
    """
    Build a stable signature from meaningful NEXUS evidence.

    Timestamps and historical counters are intentionally excluded
    so a new monitoring cycle alone does not trigger the AI.
    """

    signature_situations = []

    for situation in ai_context.get(
        "situations",
        [],
    ):

        signature_situations.append(
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
                "related_devices": situation.get(
                    "related_devices",
                    [],
                ),
            }
        )

    signature_situations.sort(
        key=lambda item: (
            str(item.get("subject")),
            str(item.get("subject_type")),
        )
    )

    signature_data = {
        "active_events": ai_context.get(
            "active_events",
            0,
        ),
        "network_devices": ai_context.get(
            "network_devices",
            0,
        ),
        "situations": signature_situations,
    }

    return json.dumps(
        signature_data,
        sort_keys=True,
        separators=(",", ":"),
    )

def should_run_ai(ai_context):
    """
    Decide whether a new AI inference should run.
    """

    state = load_trigger_state()

    current_signature = (
        build_situation_signature(
            ai_context
        )
    )

    previous_signature = state.get(
        "last_signature"
    )

    last_run_at = state.get(
        "last_run_at"
    )

    if previous_signature is None:
        return True

    if current_signature == previous_signature:
        return False

    if last_run_at is None:
        return True

    try:
        previous_time = datetime.fromisoformat(
            str(last_run_at).replace(
                "Z",
                "+00:00",
            )
        )

        elapsed = (
            datetime.now(timezone.utc)
            - previous_time
        ).total_seconds()

        return (
            elapsed
            >= AI_COOLDOWN_SECONDS
        )

    except ValueError:
        return True
def record_ai_trigger(ai_context):
    """
    Record the intelligence signature used
    for the latest AI decision.
    """

    state = {
        "last_run_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "last_signature": (
            build_situation_signature(
                ai_context
            )
        ),
    }

    AI_TRIGGER_STATE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with AI_TRIGGER_STATE.open(
        "w"
    ) as file:

        json.dump(
            state,
            file,
            indent=2,
        )

        file.write("\n")

def build_prompt(ai_context):
    """
    Build the NEXUS-specific prompt sent to the local model.
    """

    return f"""
You are NEXUS AI, a local network security analysis component.

Your job is to interpret evidence collected and scored by the
NEXUS deterministic monitoring system.

IMPORTANT:
NEXUS has already performed the detection, correlation, scoring,
and historical analysis. You must interpret that evidence, not
replace it.

Rules:

1. Use only the supplied NEXUS evidence.
2. Never invent facts.
3. Never claim an attack, compromise, spoofing, intrusion,
   unauthorized access, or malicious activity as a fact unless
   NEXUS explicitly provides evidence supporting that conclusion.
4. A MAC address change alone does NOT prove spoofing or an attack.
5. A network anomaly does NOT automatically mean compromise.
6. Distinguish observed facts from possible explanations.
7. When evidence is insufficient, say that the cause is
   undetermined.
8. Use cautious language such as "may indicate", "could be
   consistent with", or "cannot be determined from current evidence"
   when appropriate.
9. Do not invent IP addresses, devices, users, ports, vendors,
   or network actions.
10. Do not infer a specific security cause from a generic
    network anomaly.
11. Treat spoofing, unauthorized access, intrusion, compromise,
    malware, or attack as hypotheses unless the supplied NEXUS
    evidence explicitly supports that conclusion.
12. If a security cause is only possible, identify it as POSSIBLE
    and explain what additional evidence would be needed.
13. When evidence_status is UNDETERMINED, do not name a specific
    attack technique as the primary explanation. Describe the
    observed behavior and state that the cause cannot yet be determined.
14. When recommending additional investigation, prioritize collecting
    corroborating evidence such as ARP, topology, device state, and
    historical event patterns.
15. Do not recommend investigating spoofing, unauthorized access,
    compromise, or intrusion unless NEXUS evidence specifically
    supports that hypothesis.
16. Do not execute commands.
17. Do not directly modify the network.
18. Recommended actions must be safe investigation, validation,
    or monitoring steps.
19. Never recommend destructive or disruptive actions.
20. Keep the response concise and technically precise.
21. Do not reinterpret a MAC address addition or removal as the
    physical device being added to or removed from the network unless
    NEXUS explicitly reports a device discovery/removal event.
Interpretation rules:

- OBSERVED = directly supported by the supplied NEXUS evidence.
- POSSIBLE = a plausible explanation, but not proven.
- UNDETERMINED = the supplied evidence is insufficient to determine the cause.

NEXUS EVIDENCE:

{json.dumps(ai_context, indent=2)}
""".strip()


def call_ollama(prompt):
    """
    Send a structured analysis request to the local
    Ollama chat API.
    """

    payload = {
        "model": MODEL,
        "messages": [
            {
                "role": "user",
                "content": prompt,
            }
        ],
        "stream": False,
        "think": False,
        "format": AI_RESPONSE_SCHEMA,
        "options": {
            "temperature": 0,
        },
    }

    request = urllib.request.Request(
        "http://127.0.0.1:11434/api/chat",
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

        model_response = message.get(
            "content",
            "",
        )

        if not model_response:
            raise RuntimeError(
                "Ollama returned an empty AI response."
            )

        return json.loads(
            model_response
        )

    except urllib.error.URLError as error:

        raise RuntimeError(
            f"Could not connect to Ollama: {error}"
        ) from error

    except json.JSONDecodeError as error:

        raise RuntimeError(
            "Ollama returned invalid JSON: "
            + str(error)
        ) from error

def validate_result(result):
    """
    Validate the model response against the NEXUS AI contract.
    """

    required_fields = {
        "interpretation",
        "confidence",
        "recommended_action",
        "reasoning_summary",
        "evidence_status",
    }

    if not isinstance(
        result,
        dict,
    ):
        raise RuntimeError(
            "AI result is not a JSON object."
        )

    missing = (
        required_fields
        - result.keys()
    )

    if missing:
        raise RuntimeError(
            "AI result is missing fields: "
            + ", ".join(
                sorted(missing)
            )
        )

    valid_confidence = {
        "LOW",
        "MEDIUM",
        "HIGH",
    }

    if result["confidence"] not in valid_confidence:

        raise RuntimeError(
            "AI returned invalid confidence: "
            + str(
                result["confidence"]
            )
        )

    valid_evidence_status = {
        "OBSERVED",
        "POSSIBLE",
        "UNDETERMINED",
    }

    if (
        result["evidence_status"]
        not in valid_evidence_status
    ):

        raise RuntimeError(
            "AI returned invalid evidence_status: "
            + str(
                result["evidence_status"]
            )
        )

    for field in (
        "interpretation",
        "recommended_action",
        "reasoning_summary",
    ):

        if not isinstance(
            result[field],
            str,
        ) or not result[field].strip():

            raise RuntimeError(
                "AI field must contain non-empty text: "
                + field
            )

    return result

def publish_result(
    result,
    intelligence,
):
    """
    Save the validated NEXUS AI result together
    with the intelligence snapshot it analyzed.
    """

    AI_OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output = {
        "model": MODEL,
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "source_intelligence_at": (
            intelligence.get(
                "generated_at"
            )
        ),
        "source_last_event_at": (
            intelligence.get(
                "source_last_event_at"
            )
        ),
        "status": "AVAILABLE",
        "result": result,
    }

    with AI_OUTPUT.open(
        "w"
    ) as file:

        json.dump(
            output,
            file,
            indent=2,
        )

    return output

def main():

    ai_data = load_json(
        INTELLIGENCE_CURRENT
    )

    ai_context = ai_data.get(
        "ai_context",
        {},
    )

    if not ai_context:
        raise RuntimeError(
            "No ai_context found in current intelligence."
        )

    if not should_run_ai(
        ai_context
    ):

        print(
            "NEXUS AI skipped: "
            "no meaningful change or cooldown active."
        )

        return

    prompt = build_prompt(
        ai_context
    )

    result = call_ollama(
        prompt
    )

    result = validate_result(
        result
    )

    output = publish_result(
        result,
        ai_data,
    )

    record_ai_trigger(
        ai_context
    )

    print()
    print(
        "============ NEXUS AI ============"
    )
    print()
    print(
        "Model:",
        output["model"],
    )
    print(
        "Interpretation:",
        result["interpretation"],
    )
    print(
        "Confidence:",
        result["confidence"],
    )
    print(
        "Evidence status:",
        result["evidence_status"],
    )
    print(
        "Recommended action:",
        result["recommended_action"],
    )
    print(
        "Reasoning:",
        result["reasoning_summary"],
    )
    print()

if __name__ == "__main__":
    main()

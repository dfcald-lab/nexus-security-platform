#!/usr/bin/env python3

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


NEXUS = Path.home() / "nexus"

INTELLIGENCE_DIR = Path(
    os.environ.get(
        "NEXUS_INTELLIGENCE_DIR",
        str(
            NEXUS
            / "monitoring"
            / "intelligence"
        ),
    )
)

INTELLIGENCE_CURRENT = (
    INTELLIGENCE_DIR
    / "current.json"
)

AI_OUTPUT = (
    INTELLIGENCE_DIR
    / "ai_result.json"
)

AI_TRIGGER_STATE = (
    INTELLIGENCE_DIR
    / "ai_trigger_state.json"
)

AI_HISTORY = (
    INTELLIGENCE_DIR
    / "ai_history.jsonl"
)

AI_VALIDATION_STATE = (
    INTELLIGENCE_DIR
    / "ai_validation_state.json"
)


AI_COOLDOWN_SECONDS = 300
AI_STALE_SECONDS = 1800

OLLAMA_URL = (
    "http://127.0.0.1:11434/api/chat"
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
        "current_signature": None,
        "current_seen_at": None,
        "trigger_status": "UNKNOWN",
    }

    try:
        with AI_TRIGGER_STATE.open() as file:
            data = json.load(file)

        if isinstance(data, dict):
            default.update(data)

    except (OSError, json.JSONDecodeError):
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

def ai_result_is_stale(ai_context, now):
    try:
        intelligence_generated_at = (
            ai_context.get("generated_at")
        )

        if not intelligence_generated_at:
            intelligence_data = load_json(
                INTELLIGENCE_CURRENT
            )

            intelligence_generated_at = (
                intelligence_data.get(
                    "generated_at"
                )
            )

        ai_data = load_json(AI_OUTPUT)
        ai_generated_at = ai_data.get(
            "generated_at"
        )

        if not intelligence_generated_at:
            return True

        if not ai_generated_at:
            return True

        intelligence_time = datetime.fromisoformat(
            str(intelligence_generated_at).replace(
                "Z",
                "+00:00",
            )
        )

        ai_time = datetime.fromisoformat(
            str(ai_generated_at).replace(
                "Z",
                "+00:00",
            )
        )

        age = (
            intelligence_time - ai_time
        ).total_seconds()

        if age < 0:
            return False

        return age > AI_STALE_SECONDS

    except (
        OSError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ):
        return True


def should_run_ai(ai_context):
    state = load_trigger_state()

    current_signature = build_situation_signature(
        ai_context
    )

    now = datetime.now(timezone.utc)

    state["current_signature"] = current_signature
    state["current_seen_at"] = now.isoformat()

    last_signature = state.get(
        "last_signature"
    )

    last_attempt_status = str(
        state.get(
            "last_attempt_status",
            "",
        )
    ).upper()

    if (
        current_signature == last_signature
        and last_attempt_status == "REJECTED"
    ):
        last_run_at = state.get(
            "last_run_at"
        )

        if not last_run_at:
            state["trigger_status"] = "PENDING"

            AI_TRIGGER_STATE.write_text(
                json.dumps(
                    state,
                    indent=2,
                )
            )

            return True

        try:
            previous_run = datetime.fromisoformat(
                str(last_run_at).replace(
                    "Z",
                    "+00:00",
                )
            )

            elapsed = (
                now - previous_run
            ).total_seconds()

        except ValueError:
            state["trigger_status"] = "PENDING"

            AI_TRIGGER_STATE.write_text(
                json.dumps(
                    state,
                    indent=2,
                )
            )

            return True

        if elapsed >= AI_COOLDOWN_SECONDS:
            state["trigger_status"] = "PENDING"

            AI_TRIGGER_STATE.write_text(
                json.dumps(
                    state,
                    indent=2,
                )
            )

            return True

        state["trigger_status"] = "PENDING"

        AI_TRIGGER_STATE.write_text(
            json.dumps(
                state,
                indent=2,
            )
        )

        return False

    if last_signature is None:
        state["trigger_status"] = "PENDING"

        AI_TRIGGER_STATE.write_text(
            json.dumps(
                state,
                indent=2,
            )
        )

        return True

    if current_signature == last_signature:
        if ai_result_is_stale(
            ai_context,
            now,
        ):
            last_run_at = state.get(
                "last_run_at"
            )

            if not last_run_at:
                state["trigger_status"] = "PENDING"

                AI_TRIGGER_STATE.write_text(
                    json.dumps(
                        state,
                        indent=2,
                    )
                )

                return True

            try:
                previous_run = datetime.fromisoformat(
                    str(last_run_at).replace(
                        "Z",
                        "+00:00",
                    )
                )

                elapsed = (
                    now - previous_run
                ).total_seconds()

            except ValueError:
                state["trigger_status"] = "PENDING"

                AI_TRIGGER_STATE.write_text(
                    json.dumps(
                        state,
                        indent=2,
                    )
                )

                return True

            if elapsed >= AI_COOLDOWN_SECONDS:
                state["trigger_status"] = "PENDING"

                AI_TRIGGER_STATE.write_text(
                    json.dumps(
                        state,
                        indent=2,
                    )
                )

                return True

            state["trigger_status"] = "PENDING"

            AI_TRIGGER_STATE.write_text(
                json.dumps(
                    state,
                    indent=2,
                )
            )

            return False

        state["trigger_status"] = "AVAILABLE"

        AI_TRIGGER_STATE.write_text(
            json.dumps(
                state,
                indent=2,
            )
        )

        return False

    last_run_at = state.get(
        "last_run_at"
    )

    if not last_run_at:
        state["trigger_status"] = "PENDING"

        AI_TRIGGER_STATE.write_text(
            json.dumps(
                state,
                indent=2,
            )
        )

        return True

    try:
        previous_run = datetime.fromisoformat(
            str(last_run_at).replace(
                "Z",
                "+00:00",
            )
        )

        elapsed = (
            now - previous_run
        ).total_seconds()

    except ValueError:
        state["trigger_status"] = "PENDING"

        AI_TRIGGER_STATE.write_text(
            json.dumps(
                state,
                indent=2,
            )
        )

        return True

    if elapsed >= AI_COOLDOWN_SECONDS:
        state["trigger_status"] = "PENDING"

        AI_TRIGGER_STATE.write_text(
            json.dumps(
                state,
                indent=2,
            )
        )

        return True

    state["trigger_status"] = "PENDING"

    AI_TRIGGER_STATE.write_text(
        json.dumps(
            state,
            indent=2,
        )
    )

    return False

def record_ai_trigger(ai_context):
    now = datetime.now(timezone.utc).isoformat()

    state = {
        "last_run_at": now,
        "last_signature": build_situation_signature(
            ai_context
        ),
        "current_signature": build_situation_signature(
            ai_context
        ),
        "current_seen_at": now,
        "last_attempt_at": now,
        "last_attempt_status": "AVAILABLE",
        "last_attempt_error": None,
        "trigger_status": "AVAILABLE",
    }

    AI_TRIGGER_STATE.write_text(
        json.dumps(
            state,
            indent=2,
        )
    )

def build_prompt(ai_context):
    """
    Build the NEXUS-specific prompt sent to the local model.
    """

    return f"""
You are NEXUS AI, a local network security analysis component.

Your job is to interpret evidence collected and scored by the
NEXUS deterministic monitoring system.

IMPORTANT:
NEXUS has already performed detection, correlation, scoring,
and historical analysis. Interpret that evidence. Do not replace it.

Rules:

1. Use only the supplied NEXUS evidence.
2. Never invent facts, devices, users, IP addresses, ports, vendors,
   identities, causes, or network actions.
3. Report facts exactly as supported by the supplied evidence.
4. Distinguish observed facts from possible explanations.
5. When the cause is not established, use evidence_status:
   UNDETERMINED.
6. When evidence_status is UNDETERMINED, describe observed behavior
   without assigning a cause.
7. When evidence_status is UNDETERMINED, recommended_action must
   focus only on neutral monitoring, validation, evidence collection,
   or configuration/state checking.
8. For UNDETERMINED results, preferred action language includes:
   "monitor for recurrence", "validate the observed state",
   "collect additional evidence", "review current configuration",
   and "check device or port state".
9. For UNDETERMINED results, do not use security-incident language
   such as "unauthorized access", "intrusion", "attack", "compromise",
   "spoofing", or "malware" in any field.
10. Never recommend destructive or disruptive actions.
11. Do not execute commands or directly modify the network.
12. Keep the response concise and technically precise.

AUTHORITATIVE METRIC RULES:

13. Structured NEXUS metrics are authoritative.
14. Numeric metrics must not be contradicted or reinterpreted.
15. Zero-valued metrics are explicit observations, not missing data.
16. mac_added and mac_removed describe MAC-address observations.
17. identity_changes is a separate metric from MAC-address changes.
18. port_changes is a separate metric from MAC-address changes.
19. If identity_changes is 0, no identity changes were observed.
20. If port_changes is 0, no port changes were observed.
21. If mac_added is greater than 0, MAC-address additions were observed.
22. If mac_removed is greater than 0, MAC-address removals were observed.
23. Do not infer identity_changes from mac_added or mac_removed.
24. Do not infer port_changes when port_changes is 0.
25. An assessment label is descriptive and does not override its metrics.
26. The phrase "network identity churn" does not by itself mean
    identity_changes occurred.
27. Do not describe a device as unknown when NEXUS identifies it.
28. Do not introduce a new explanation that is unsupported by the
    supplied structured evidence.

INTERPRETATION RULES:

- OBSERVED = directly supported by the supplied NEXUS evidence.
- POSSIBLE = a plausible explanation, but not proven.
- UNDETERMINED = the supplied evidence is insufficient to determine
  the cause.

NEXUS EVIDENCE:

{json.dumps(ai_context, indent=2)}
""".strip()


def call_ollama(prompt):
    """
    Send a structured analysis request to the local
    Ollama chat API.
    """

    parsed_url = urllib.parse.urlparse(
        OLLAMA_URL
    )

    allowed_hosts = {
        "127.0.0.1",
        "localhost",
        "::1",
    }

    if (
        parsed_url.scheme != "http"
        or parsed_url.hostname not in allowed_hosts
        or parsed_url.port != 11434
        or parsed_url.path != "/api/chat"
    ):
        raise RuntimeError(
            "NEXUS AI refused a non-local Ollama endpoint: "
            + OLLAMA_URL
        )

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

def append_ai_history(
    result,
    intelligence,
    generated_at,
):
    AI_HISTORY.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    record = {
        "generated_at": generated_at,
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
        "model": MODEL,
        "result": result,
    }

    with AI_HISTORY.open(
        "a",
        encoding="utf-8",
    ) as file:

        json.dump(
            record,
            file,
            separators=(",", ":"),
        )

        file.write("\n")


def validate_evidence_language(result):
    """
    Enforce NEXUS language rules after model generation.
    """

    if result.get("evidence_status") != "UNDETERMINED":
        return result

    blocked_terms = (
        "spoofing",
        "unauthorized access",
        "compromise",
        "intrusion",
        "malware",
        "attack",
    )

    fields_to_check = (
        "interpretation",
        "recommended_action",
        "reasoning_summary",
    )

    for field in fields_to_check:
        text = str(
            result.get(
                field,
                "",
            )
        ).lower()

        for term in blocked_terms:
            if term in text:
                raise RuntimeError(
                    "AI result violates UNDETERMINED "
                    "evidence policy: "
                    + field
                    + " contains "
                    + repr(term)
                )

    return result


def record_ai_validation_success(
    intelligence,
):
    """
    Record that the latest AI result passed NEXUS validation.
    A previous rejection is therefore no longer current.
    """

    now = datetime.now(
        timezone.utc
    ).isoformat()

    validation_state = {
        "status": "PASSED",
        "attempted_at": now,
        "source_intelligence_at": intelligence.get(
            "generated_at"
        ),
        "error": None,
    }

    AI_VALIDATION_STATE.write_text(
        json.dumps(
            validation_state,
            indent=2,
        )
        + "\n"
    )


def record_ai_rejection(
    error_message,
    intelligence,
):
    """
    Record a rejected AI attempt without publishing the result.
    The previous valid AI result remains intact.
    """

    now = datetime.now(
        timezone.utc
    ).isoformat()

    source_intelligence_at = intelligence.get(
        "generated_at"
    )

    validation_state = {
        "status": "REJECTED",
        "attempted_at": now,
        "source_intelligence_at": source_intelligence_at,
        "error": str(error_message),
    }

    AI_VALIDATION_STATE.write_text(
        json.dumps(
            validation_state,
            indent=2,
        )
        + "\n"
    )

    trigger_state = load_trigger_state()

    trigger_state["last_run_at"] = now
    trigger_state["last_attempt_at"] = now
    trigger_state["last_attempt_status"] = "REJECTED"
    trigger_state["last_attempt_error"] = str(
        error_message
    )
    trigger_state["trigger_status"] = "PENDING"

    AI_TRIGGER_STATE.write_text(
        json.dumps(
            trigger_state,
            indent=2,
        )
        + "\n"
    )


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

    append_ai_history(
        result,
        intelligence,
        output["generated_at"],
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

    try:
        result = validate_evidence_language(
            result
        )
    except RuntimeError as exc:
        record_ai_rejection(
            str(exc),
            ai_data,
        )

        print(
            "NEXUS AI rejected:",
            exc,
        )

        return

    output = publish_result(
        result,
        ai_data,
    )

    record_ai_validation_success(
        ai_data
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

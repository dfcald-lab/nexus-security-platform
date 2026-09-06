#!/usr/bin/env python3

import json
import urllib.error
import urllib.request
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

OLLAMA_URL = (
    "http://127.0.0.1:11434/api/generate"
)

MODEL = "qwen3:1.7b"


def load_json(path):
    with path.open("r") as file:
        return json.load(file)

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
10. Do not execute commands.
11. Do not directly modify the network.
12. Recommended actions must be safe investigation, validation,
    or monitoring steps.
13. Never recommend destructive or disruptive actions.
14. Keep the response concise and technically precise.

Return ONLY valid JSON with exactly these fields:

{{
  "interpretation": "A concise interpretation supported by the evidence.",
  "confidence": "LOW, MEDIUM, or HIGH",
  "recommended_action": "A safe investigation, validation, or monitoring step.",
  "reasoning_summary": "The specific evidence supporting the interpretation.",
  "evidence_status": "OBSERVED, POSSIBLE, or UNDETERMINED"
}}

Interpretation rules:

- OBSERVED = directly supported by the supplied NEXUS evidence.
- POSSIBLE = a plausible explanation, but not proven.
- UNDETERMINED = the supplied evidence is insufficient to determine the cause.

NEXUS EVIDENCE:

{json.dumps(ai_context, indent=2)}
""".strip()


def call_ollama(prompt):
    """
    Send a prompt to the local Ollama server.
    """

    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json",
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

        model_response = response_data.get(
            "response",
            "",
        )

        if not model_response:
            raise RuntimeError(
                "Ollama returned an empty response."
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
            "Ollama returned invalid JSON."
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

def publish_result(result):
    """
    Save the validated NEXUS AI result.
    """

    AI_OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output = {
        "model": MODEL,
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
        result
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

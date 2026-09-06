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

Rules:

1. Use only the supplied evidence.
2. Do not invent facts.
3. Do not claim an attack occurred unless the evidence supports it.
4. Do not invent IP addresses, devices, users, or actions.
5. Do not execute commands.
6. Do not directly modify the network.
7. Recommended actions must be investigation or observation steps.
8. Distinguish facts from possibilities.
9. Be concise and technically precise.

Return ONLY valid JSON with exactly these fields:

{{
  "interpretation": "What the evidence most likely means.",
  "confidence": "LOW, MEDIUM, or HIGH",
  "recommended_action": "A safe investigation or monitoring recommendation.",
  "reasoning_summary": "The evidence supporting the interpretation."
}}

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

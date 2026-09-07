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

RED_TEAM_OUTPUT = (
    INTELLIGENCE_DIR
    / "red_team_result.json"
)

RED_TEAM_HISTORY = (
    INTELLIGENCE_DIR
    / "red_team_history.jsonl"
)

OLLAMA_URL = (
    "http://127.0.0.1:11434/api/chat"
)

MODEL = "qwen3:1.7b"


RED_TEAM_SCHEMA = {
    "type": "object",
    "properties": {
        "target": {
            "type": "string"
        },
        "attack_surface": {
            "type": "string"
        },
        "objective": {
            "type": "string"
        },
        "hypothesis": {
            "type": "string"
        },
        "priority": {
            "type": "string",
            "enum": [
                "LOW",
                "MEDIUM",
                "HIGH",
            ],
        },
        "validation_plan": {
            "type": "array",
            "items": {
                "type": "string"
            },
            "maxItems": 6,
        },
        "expected_evidence": {
            "type": "string"
        },
        "safety_note": {
            "type": "string"
        },
    },
    "required": [
        "target",
        "attack_surface",
        "objective",
        "hypothesis",
        "priority",
        "validation_plan",
        "expected_evidence",
        "safety_note",
    ],
    "additionalProperties": False,
}


BLOCKED_PATTERNS = (
    "perform denial of service",
    "launch a denial of service",
    "execute a dos attack",
    "launch a dos attack",
    "launch a ddos",
    "steal credentials",
    "harvest credentials",
    "perform credential theft",
    "perform password spraying",
    "perform credential stuffing",
    "establish persistence",
    "create persistence",
    "install persistence",
    "deploy a payload",
    "execute a payload",
    "open a reverse shell",
    "establish a reverse shell",
    "install a backdoor",
    "create a backdoor",
    "exfiltrate data",
    "steal data",
    "evade detection",
    "disable logging",
)


def load_intelligence():
    with INTELLIGENCE_CURRENT.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


def validate_result(result):
    required = {
        "target",
        "attack_surface",
        "objective",
        "hypothesis",
        "priority",
        "validation_plan",
        "expected_evidence",
        "safety_note",
    }

    if not isinstance(result, dict):
        raise RuntimeError(
            "RED TEAM result is not an object."
        )

    missing = required - result.keys()

    if missing:
        raise RuntimeError(
            "RED TEAM result missing fields: "
            + ", ".join(sorted(missing))
        )

    if result["priority"] not in {
        "LOW",
        "MEDIUM",
        "HIGH",
    }:
        raise RuntimeError(
            "RED TEAM returned invalid priority."
        )

    if not isinstance(
        result["validation_plan"],
        list,
    ):
        raise RuntimeError(
            "RED TEAM validation_plan must be a list."
        )

    if not result["validation_plan"]:
        raise RuntimeError(
            "RED TEAM validation_plan cannot be empty."
        )

    if len(result["validation_plan"]) > 6:
        raise RuntimeError(
            "RED TEAM validation_plan is too large."
        )

    for field in (
        "target",
        "attack_surface",
        "objective",
        "hypothesis",
        "expected_evidence",
        "safety_note",
    ):
        if not isinstance(
            result[field],
            str,
        ) or not result[field].strip():
            raise RuntimeError(
                "RED TEAM field is empty: "
                + field
            )

    for step in result["validation_plan"]:
        if not isinstance(step, str):
            raise RuntimeError(
                "RED TEAM validation steps must be strings."
            )

    combined = " ".join(
        [
            result["objective"],
            result["hypothesis"],
            result["expected_evidence"],
            result["safety_note"],
            *result["validation_plan"],
        ]
    ).lower()

    for pattern in BLOCKED_PATTERNS:
        if pattern in combined:
            raise RuntimeError(
                "RED TEAM result contains blocked activity: "
                + repr(pattern)
            )

    return result


def select_target(ai_context):
    """
    Select the highest-priority actionable NEXUS situation.

    Target selection remains deterministic; the language model
    does not choose the target.
    """

    situations = ai_context.get(
        "situations",
        [],
    )

    actionable = [
        situation
        for situation in situations
        if situation.get(
            "highest_score",
            0,
        ) > 0
        and situation.get(
            "risk",
            "NORMAL",
        ) != "NORMAL"
    ]

    if not actionable:
        return None

    actionable.sort(
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

    return actionable[0]


def validate_metric_consistency(
    result,
    target,
):
    """
    Ensure RED TEAM does not reinterpret deterministic NEXUS metrics.
    """

    metrics = target.get(
        "metrics",
        {},
    )

    mac_added = int(
        metrics.get(
            "mac_added",
            0,
        )
    )

    mac_removed = int(
        metrics.get(
            "mac_removed",
            0,
        )
    )

    identity_changes = int(
        metrics.get(
            "identity_changes",
            0,
        )
    )

    port_changes = int(
        metrics.get(
            "port_changes",
            0,
        )
    )

    combined = " ".join(
        [
            result.get(
                "hypothesis",
                "",
            ),
            result.get(
                "objective",
                "",
            ),
            result.get(
                "expected_evidence",
                "",
            ),
            *result.get(
                "validation_plan",
                [],
            ),
        ]
    ).lower()

    if identity_changes == 0:

        observed_identity_patterns = (
            "the device changed its identity",
            "the device changed its network identity",
            "the device was configured with a new identity",
            "the device was configured with a new network identity",
            "the device identity changed",
            "the network identity changed",
            "the network identity was changed",
            "a new network identity was observed",
            "a new device identity was observed",
        )

        for pattern in observed_identity_patterns:

            if pattern in combined:

                raise RuntimeError(
                    "RED TEAM contradicted NEXUS metric: "
                    "identity_changes=0 but output contains "
                    + repr(pattern)
                )

    if port_changes == 0:

        observed_port_patterns = (
            "device moved from",
            "device was moved from",
            "device moved to",
            "device was moved to",
            "device has moved from",
            "device has moved to",
            "the device moved",
            "the device was moved",
            "the port changed from",
            "the port was changed from",
            "the port changed to",
            "the port was changed to",
        )

        for pattern in observed_port_patterns:

            if pattern in combined:

                raise RuntimeError(
                    "RED TEAM contradicted NEXUS metric: "
                    "port_changes=0 but output contains "
                    + repr(pattern)
                )

    if mac_added == 0:

        mac_add_terms = (
            "mac address was added",
            "mac address has been added",
            "new mac address was added",
            "new mac address has been added",
            "additional mac was added",
            "additional mac has been added",
        )

        for term in mac_add_terms:

            if term in combined:

                raise RuntimeError(
                    "RED TEAM contradicted NEXUS metric: "
                    "mac_added=0 but output contains "
                    + repr(term)
                )

    if mac_removed == 0:

        mac_remove_terms = (
            "mac address was removed",
            "mac address has been removed",
            "mac address was deleted",
            "additional mac was removed",
            "additional mac has been removed",
        )

        for term in mac_remove_terms:

            if term in combined:

                raise RuntimeError(
                    "RED TEAM contradicted NEXUS metric: "
                    "mac_removed=0 but output contains "
                    + repr(term)
                )

    return result


def calculate_priority(
    target,
):
    """
    Convert the deterministic NEXUS event score into
    a RED TEAM priority.
    """

    score = int(
        target.get(
            "highest_score",
            0,
        )
    )

    if score >= 25:
        return "HIGH"

    if score >= 15:
        return "MEDIUM"

    return "LOW"



def build_prompt(ai_context, target):
    return f"""
You are NEXUS RED TEAM, an authorized security validation
assistant operating inside a controlled network environment.

NEXUS deterministic monitoring has already selected the target
for this assessment.

You MUST use the supplied SELECTED TARGET exactly.
Do not replace, rename, or invent the target.

SELECTED TARGET:
{json.dumps(target, indent=2)}

NEXUS deterministic monitoring has already collected, correlated,
and scored the evidence below.

Your role is to think like a penetration tester, but only produce
safe, authorized, non-destructive validation guidance.

Rules:

1. Use only the supplied NEXUS evidence.
2. Never invent hosts, users, IP addresses, credentials, ports,
   vulnerabilities, software versions, or causes.
3. Treat every hypothesis as unproven unless the evidence directly
   establishes it.
4. Separate observed facts from testing hypotheses.
5. Focus on attack-surface identification, security weaknesses,
   configuration validation, exposure analysis, and safe testing.
6. Validation steps must be non-destructive and suitable for an
   authorized lab or controlled enterprise assessment.
7. Do not provide denial-of-service, destructive, persistence,
   credential-theft, malware, evasion, exfiltration, or backdoor
   instructions.
8. Do not provide autonomous attack commands.
9. Do not modify the network.
10. Prefer read-only inspection, configuration review, evidence
    collection, controlled verification, and tabletop validation.
11. Do not claim that a weakness exists unless NEXUS evidence supports it.
12. Keep the validation plan concise and actionable for an authorized
    security engineer.
13. When evidence is insufficient, explicitly describe the hypothesis
    as unconfirmed.
14. mac_added is not identity_changes. A MAC addition alone must never
    be described as a confirmed identity change.
15. identity_changes = 0 means no identity change was observed.
16. port_changes = 0 means no port movement was observed.
17. Use exact NEXUS metric values when describing observed activity.
18. mac_added describes a MAC-address addition, not a confirmed identity change.
19. Only describe an identity change as observed when identity_changes is greater
    than 0.
20. Only describe port movement as observed when port_changes is greater than 0.
21. RED TEAM priority is assigned by NEXUS from highest_score and must not be
    inferred independently by the model.

NEXUS EVIDENCE:

{json.dumps(ai_context, indent=2)}
""".strip()


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
            "NEXUS RED TEAM refused a non-local Ollama endpoint: "
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
        "format": RED_TEAM_SCHEMA,
        "options": {
            "temperature": 0,
        },
    }

    request = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode(
            "utf-8"
        ),
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

        response_data = json.loads(raw)

        content = response_data.get(
            "message",
            {},
        ).get(
            "content",
            "",
        )

        if not content:
            raise RuntimeError(
                "Ollama returned an empty RED TEAM response."
            )

        return json.loads(content)

    except urllib.error.URLError as error:
        raise RuntimeError(
            f"Could not connect to Ollama: {error}"
        ) from error

    except json.JSONDecodeError as error:
        raise RuntimeError(
            "Ollama returned invalid RED TEAM JSON: "
            + str(error)
        ) from error


def publish_result(result, intelligence):
    RED_TEAM_OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output = {
        "model": MODEL,
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "source_intelligence_at": intelligence.get(
            "generated_at"
        ),
        "status": "AVAILABLE",
        "role": "RED_TEAM",
        "result": result,
    }

    RED_TEAM_OUTPUT.write_text(
        json.dumps(
            output,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    history = {
        "generated_at": output[
            "generated_at"
        ],
        "source_intelligence_at": output[
            "source_intelligence_at"
        ],
        "model": MODEL,
        "role": "RED_TEAM",
        "result": result,
    }

    with RED_TEAM_HISTORY.open(
        "a",
        encoding="utf-8",
    ) as file:
        file.write(
            json.dumps(
                history,
                separators=(",", ":"),
            )
            + "\n"
        )

    return output


def main():
    intelligence = load_intelligence()

    ai_context = intelligence.get(
        "ai_context",
        {},
    )

    if not ai_context:
        raise RuntimeError(
            "No ai_context found in current intelligence."
        )

    target = select_target(
        ai_context
    )

    if target is None:
        print(
            "NEXUS RED TEAM skipped: "
            "no actionable situation selected."
        )
        return

    prompt = build_prompt(
        ai_context,
        target,
    )

    result = call_ollama(
        prompt
    )

    result = validate_result(
        result
    )

    result["target"] = target.get(
        "subject",
        "UNKNOWN",
    )

    result = validate_metric_consistency(
        result,
        target,
    )

    result["target"] = target.get(
        "subject",
        "UNKNOWN",
    )

    result["priority"] = calculate_priority(
        target
    )

    output = publish_result(
        result,
        intelligence,
    )

    print()
    print(
        "============ NEXUS RED TEAM ============"
    )
    print()
    print(
        "Model:",
        output["model"],
    )
    print(
        "Target:",
        result["target"],
    )
    print(
        "Attack surface:",
        result["attack_surface"],
    )
    print(
        "Priority:",
        result["priority"],
    )
    print(
        "Hypothesis:",
        result["hypothesis"],
    )
    print(
        "Objective:",
        result["objective"],
    )

    print()
    print("Validation plan:")

    for index, step in enumerate(
        result["validation_plan"],
        start=1,
    ):
        print(
            f"  {index}. {step}"
        )

    print()
    print(
        "Expected evidence:",
        result["expected_evidence"],
    )
    print(
        "Safety:",
        result["safety_note"],
    )
    print()


if __name__ == "__main__":
    main()

import unittest

from scripts.agent.event_classifier import (
    NORMAL,
    SIGNIFICANT,
    SUSPICIOUS,
    classify_event,
)
from scripts.agent.nexus_redteam import (
    calculate_priority,
    select_target,
    validate_metric_consistency,
    validate_result,
)
from scripts.operator.htb.service_parser import parse_nmap_table


class EventClassifierTests(unittest.TestCase):
    def test_normal_mac_churn(self):
        self.assertEqual(
            classify_event("MAC count changed on port", "MEDIUM", 15),
            NORMAL,
        )

    def test_device_move_is_significant(self):
        self.assertEqual(
            classify_event("Device moved: port A -> port B", "MEDIUM", 15),
            SIGNIFICANT,
        )

    def test_new_device_is_suspicious(self):
        self.assertEqual(
            classify_event("New network device detected", "HIGH", 25),
            SUSPICIOUS,
        )


class RedTeamValidationTests(unittest.TestCase):
    def test_priority_uses_deterministic_score(self):
        self.assertEqual(calculate_priority({"highest_score": 5}), "LOW")
        self.assertEqual(calculate_priority({"highest_score": 15}), "MEDIUM")
        self.assertEqual(calculate_priority({"highest_score": 25}), "HIGH")

    def test_target_selection_is_deterministic(self):
        context = {
            "situations": [
                {"subject": "low", "highest_score": 15, "event_count": 4, "risk": "MEDIUM"},
                {"subject": "high", "highest_score": 25, "event_count": 1, "risk": "HIGH"},
            ]
        }
        self.assertEqual(select_target(context)["subject"], "high")

    def test_metric_consistency_rejects_unsupported_identity_change(self):
        target = {"metrics": {"identity_changes": 0}}
        result = {
            "hypothesis": "The device changed its identity",
            "objective": "Validate the observed condition",
            "expected_evidence": "Configuration evidence",
            "validation_plan": ["Review the relevant configuration"],
        }
        with self.assertRaises(RuntimeError):
            validate_metric_consistency(result, target)

    def test_safe_result_passes_validation(self):
        result = {
            "target": "observed situation",
            "attack_surface": "service exposure",
            "objective": "Validate configuration",
            "hypothesis": "A configuration weakness may exist",
            "priority": "MEDIUM",
            "validation_plan": ["Review configuration", "Collect supporting evidence"],
            "expected_evidence": "Configuration state supporting or disproving the hypothesis",
            "safety_note": "Read-only validation only",
        }
        self.assertEqual(validate_result(result), result)

    def test_blocked_result_is_rejected(self):
        result = {
            "target": "observed situation",
            "attack_surface": "service exposure",
            "objective": "steal credentials",
            "hypothesis": "Unsupported",
            "priority": "HIGH",
            "validation_plan": ["Review configuration"],
            "expected_evidence": "None",
            "safety_note": "Unsafe",
        }
        with self.assertRaises(RuntimeError):
            validate_result(result)


class ServiceParserTests(unittest.TestCase):
    def test_nmap_service_table(self):
        text = """
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp   open  http    Apache httpd 2.4.41
8080/tcp open  http    Apache Tomcat 9.0.65
"""
        services = parse_nmap_table(text)

        self.assertEqual(len(services), 3)
        self.assertEqual(services[0]["port"], 22)
        self.assertEqual(services[0]["service"], "ssh")
        self.assertEqual(services[0]["version"], "OpenSSH 8.2p1 Ubuntu")
        self.assertEqual(services[2]["port"], 8080)
        self.assertEqual(services[2]["service"], "http")

    def test_invalid_lines_are_ignored(self):
        services = parse_nmap_table("Not an nmap line\n\n445/tcp open microsoft-ds")
        self.assertEqual(len(services), 1)
        self.assertEqual(services[0]["port"], 445)


if __name__ == "__main__":
    unittest.main()

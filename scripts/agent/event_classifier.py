#!/usr/bin/env python3


NORMAL = "NORMAL"
SIGNIFICANT = "SIGNIFICANT"
SUSPICIOUS = "SUSPICIOUS"


def classify_event(
    message,
    severity,
    score,
):
    """
    Classify an existing NEXUS event without changing
    the underlying event detection system.
    """

    text = message.lower()

    # --------------------------------------------------------
    # NORMAL NETWORK CHURN
    # --------------------------------------------------------

    if (
        "mac count changed" in text
        or "network health metric changed" in text
        or "mac table changed" in text
        or "mac added to device" in text
        or "mac removed from device" in text
    ):
        return NORMAL

    # --------------------------------------------------------
    # SIGNIFICANT DEVICE EVENTS
    # --------------------------------------------------------

    if (
        "device moved:" in text
        or "device removed:" in text
    ):
        return SIGNIFICANT

    # --------------------------------------------------------
    # SUSPICIOUS EVENTS
    # --------------------------------------------------------

    if (
        "mac identity changed" in text
        or "new network device detected" in text
    ):
        return SUSPICIOUS

    if (
        "device discovered:" in text
        and severity in {
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        }
    ):
        return SUSPICIOUS

    # --------------------------------------------------------
    # FALLBACK
    # --------------------------------------------------------

    if severity in {
        "HIGH",
        "CRITICAL",
    }:
        return SUSPICIOUS

    if severity == "MEDIUM":
        return SIGNIFICANT

    return NORMAL

#!/usr/bin/env python3

from pathlib import Path


HISTORY_FILE = (
    Path.home()
    / "nexus"
    / "monitoring"
    / "devices"
    / "device_history.json"
)


def normalize_mac(mac):
    if not mac:
        return ""

    return (
        mac.strip()
        .lower()
        .replace("-", "")
        .replace(":", "")
        .replace(".", "")
    )


def macs_match(mac_a, mac_b):
    normalized_a = normalize_mac(mac_a)
    normalized_b = normalize_mac(mac_b)

    return (
        bool(normalized_a)
        and bool(normalized_b)
        and normalized_a == normalized_b
    )


def load_device_history(path=HISTORY_FILE):
    import json

    if not path.exists():
        return {"devices": {}}

    try:
        with path.open("r") as file:
            data = json.load(file)

    except (OSError, json.JSONDecodeError):
        return {"devices": {}}

    if not isinstance(data, dict):
        return {"devices": {}}

    if not isinstance(data.get("devices"), dict):
        data["devices"] = {}

    return data


def find_device_by_mac(history, mac):
    for device_id, record in history.get(
        "devices",
        {},
    ).items():

        current = record.get(
            "current",
            {},
        )

        current_mac = current.get(
            "mac",
            "",
        )

        if macs_match(
            mac,
            current_mac,
        ):
            return device_id

        for known_mac in current.get(
            "mac_addresses",
            [],
        ):

            if macs_match(
                mac,
                known_mac,
            ):
                return device_id

        historical = record.get(
            "history",
            {},
        )

        for old_mac in historical.get(
            "previous_macs",
            [],
        ):

            if macs_match(
                mac,
                old_mac,
            ):
                return device_id

    return None


def find_device_by_ip(history, ip):
    if not ip or ip == "Unknown":
        return None

    for device_id, record in history.get(
        "devices",
        {},
    ).items():

        current = record.get(
            "current",
            {},
        )

        if current.get("ip") == ip:
            return device_id

        if ip in current.get(
            "ip_addresses",
            [],
        ):
            return device_id

        historical = record.get(
            "history",
            {},
        )

        if ip in historical.get(
            "previous_ips",
            [],
        ):
            return device_id

    return None


def resolve_device_identity(
    device,
    history=None,
):
    if history is None:
        history = load_device_history()

    for mac in device.get(
        "mac_addresses",
        [],
    ):

        device_id = find_device_by_mac(
            history,
            mac,
        )

        if device_id:
            return device_id

    primary_mac = device.get(
        "mac",
        "",
    )

    device_id = find_device_by_mac(
        history,
        primary_mac,
    )

    if device_id:
        return device_id

    ip = device.get(
        "ip",
        "Unknown",
    )

    device_id = find_device_by_ip(
        history,
        ip,
    )

    if device_id:
        return device_id

    return device.get(
        "device_id",
        primary_mac or "UNKNOWN",
    )


def resolve_inventory_identities(
    inventory,
    history=None,
):
    if history is None:
        history = load_device_history()

    devices = inventory.get(
        "devices",
        {},
    )

    resolved_devices = {}

    for transient_id, device in devices.items():

        resolved_id = resolve_device_identity(
            device,
            history,
        )

        device["device_id"] = resolved_id

        # Preserve the canonical primary MAC when this
        # observation matches an existing device.
        existing_record = history.get(
            "devices",
            {},
        ).get(
            resolved_id
        )

        if existing_record:
            canonical_mac = existing_record.get(
                "device_id",
                "",
            )

            if canonical_mac:
                device["mac"] = canonical_mac

        resolved_devices[resolved_id] = device
    
    inventory["devices"] = resolved_devices

    return inventory

#!/usr/bin/env python3

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


# ============================================================
# NEXUS DEVICE HISTORY
# ============================================================

HISTORY_DIR = (
    Path.home()
    / "nexus"
    / "monitoring"
    / "devices"
)

HISTORY_FILE = (
    HISTORY_DIR
    / "device_history.json"
)


# ============================================================
# TIME
# ============================================================

def current_timestamp():
    return datetime.now(
        timezone.utc
    ).isoformat()


# ============================================================
# LOAD / SAVE
# ============================================================

def load_history():

    if not HISTORY_FILE.exists():
        return {
            "devices": {}
        }

    try:

        with HISTORY_FILE.open("r") as file:
            data = json.load(file)

        if not isinstance(data, dict):
            return {
                "devices": {}
            }

        if not isinstance(
            data.get("devices"),
            dict,
        ):
            data["devices"] = {}

        return data

    except (
        json.JSONDecodeError,
        OSError,
    ):

        return {
            "devices": {}
        }


def save_history(history):

    HISTORY_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary = HISTORY_FILE.with_suffix(
        ".tmp"
    )

    with temporary.open("w") as file:

        json.dump(
            history,
            file,
            indent=2,
            sort_keys=False,
        )

    temporary.replace(
        HISTORY_FILE
    )


# ============================================================
# HELPERS
# ============================================================

def unique_list(values):

    result = []

    for value in values:

        if not value:
            continue

        if value not in result:
            result.append(value)

    return result


def add_history_value(
    history_list,
    value,
):

    if not value:
        return

    if value == "Unknown":
        return

    if value not in history_list:

        history_list.append(
            value
        )


# ============================================================
# DEVICE HISTORY UPDATE
# ============================================================

def update_device_history(
    inventory,
):

    history = load_history()

    devices = inventory.get(
        "devices",
        {},
    )

    now = current_timestamp()

    new_devices = 0
    moved_devices = 0
    changed_mac_devices = 0
    changed_ip_devices = 0


    events = []

    for device_id, device in devices.items():

        current_port = device.get(
            "port",
            "Unknown",
        )

        current_macs = unique_list(
            device.get(
                "mac_addresses",
                [],
            )
        )

        current_ips = unique_list(
            device.get(
                "ip_addresses",
                [],
            )
        )

        current_ip = device.get(
            "ip",
            "Unknown",
        )

        if (
            current_ip != "Unknown"
            and current_ip not in current_ips
        ):
            current_ips.insert(
                0,
                current_ip,
            )

        device_type = device.get(
            "device_type",
            "UNKNOWN",
        )

        vendor = device.get(
            "vendor",
            "Unknown",
        )

        description = device.get(
            "description",
            "",
        )

        # ----------------------------------------------------
        # NEW DEVICE
        # ----------------------------------------------------

        if device_id not in history["devices"]:

            history["devices"][device_id] = {
                "device_id": device_id,
                "first_seen": now,
                "last_seen": now,
                "observations": 1,

                "current": {
                    "port": current_port,
                    "mac": device.get(
                        "mac",
                        device_id,

		      ),
                    "vlan": device.get(
                    "vlan",
                        "Unknown",
                    ),
                    "ip": current_ip,
                    "ip_addresses": current_ips,
                    "mac_addresses": current_macs,
                    "device_type": device_type,
                    "vendor": vendor,
                    "description": description,
                },

                "history": {
                    "previous_ports": [],
                    "previous_macs": [],
                    "previous_ips": [],
                },
            }

            new_devices += 1

            continue

        # ----------------------------------------------------
        # EXISTING DEVICE
        # ----------------------------------------------------

        record = history["devices"][device_id]

        current = record.setdefault(
            "current",
            {},
        )

        historical = record.setdefault(
            "history",
            {
                "previous_ports": [],
                "previous_macs": [],
                "previous_ips": [],
            },
        )

        historical.setdefault(
            "previous_ports",
            [],
        )

        historical.setdefault(
            "previous_macs",
            [],
        )

        historical.setdefault(
            "previous_ips",
            [],
        )

        old_port = current.get(
            "port",
            "Unknown",
        )

        new_port = device.get(
            "port",
            "Unknown",
        )

        old_macs = set(
            current.get(
                "mac_addresses",
                [],
            )
        )

        old_ips = set(
            current.get(
                "ip_addresses",
                [],
            )
        )

        new_macs = set(
            current_macs
        )

        new_ips = set(
            current_ips
        )

        # ----------------------------------------------------
        # PORT MOVEMENT
        # ----------------------------------------------------

        if (
            old_port != new_port
            and old_port != "Unknown"
            and new_port != "Unknown"
        ):

            add_history_value(
                historical[
                    "previous_ports"
                ],
                old_port,
            )

            moved_devices += 1


            events.append(
                {
                    "event": "DEVICE_MOVED",
                    "device_id": device_id,
                    "device_type": device.get(
                        "device_type",
                        "UNKNOWN",
                    ),
                    "vendor": device.get(
                        "vendor",
                        "Unknown",
                    ),
                    "from_port": old_port,
                    "to_port": current_port,
                    "ip": device.get(
                        "ip",
                        "Unknown",
                    ),
                }
            )

        # ----------------------------------------------------
        # MAC HISTORY
        # ----------------------------------------------------
        #
        # The primary MAC identifies the logical device.
        #
        # A device may expose multiple MAC addresses through
        # one physical switch port. Those secondary MACs can
        # appear/disappear as the switch relearns its MAC table.
        #
        # Therefore, disappearing observed MACs are NOT treated
        # as a device identity change.
        #
        # Only a change to the primary MAC is a true MAC change.
        # ----------------------------------------------------

        old_primary_mac = current.get(
            "mac",
            device_id,
        )

        new_primary_mac = device.get(
            "mac",
            device_id,
        )

        if (
            old_primary_mac
            and new_primary_mac
            and old_primary_mac != new_primary_mac
        ):

            add_history_value(
                historical[
                    "previous_macs"
                ],
                old_primary_mac,
            )

            changed_mac_devices += 1

        # ----------------------------------------------------
        # IP HISTORY
        # ----------------------------------------------------

        removed_ips = old_ips - new_ips

        for ip in sorted(
            removed_ips
        ):

            add_history_value(
                historical[
                    "previous_ips"
                ],
                ip,
            )

        if removed_ips:
            changed_ip_devices += 1

        # ----------------------------------------------------
        # UPDATE CURRENT STATE
        # ----------------------------------------------------

        current["port"] = current_port

        current["mac"] = device.get(
            "mac",
            device_id,
        )

        current["vlan"] = device.get(
            "vlan",
            "Unknown",
        )

        current["ip"] = current_ip
        current["ip_addresses"] = current_ips

        current["mac_addresses"] = current_macs

        # ----------------------------------------------------
        # PRESERVE DEVICE IDENTITY
        # ----------------------------------------------------
        #
        # Device identity belongs to the device, not the
        # switch port. A port description such as "TV" must
        # not change a previously learned Steam Deck into
        # a television when the device moves.
        #
        # Only populate identity when it does not already
        # exist in persistent history.

        if not current.get("device_type"):
            current["device_type"] = device_type

        if (
            not current.get("vendor")
            or current.get("vendor") == "Unknown"
        ):
            if vendor != "Unknown":
                current["vendor"] = vendor

        if not current.get("description"):
            current["description"] = description

        record["last_seen"] = now

        record["observations"] = (
            record.get(
                "observations",
                0,
            )
            + 1
        )

    save_history(
        history
    )

    return (
        history,
        new_devices,
        moved_devices,
        changed_mac_devices,
        changed_ip_devices,
	events,
    )


# ============================================================
# OUTPUT
# ============================================================

def print_history_summary(
    history,
    new_devices,
    moved_devices,
    changed_mac_devices,
    changed_ip_devices,
    events,
):

    print()
    print(
        "===================================="
    )
    print(
        "        NEXUS DEVICE HISTORY"
    )
    print(
        "===================================="
    )
    print()

    print(
        f"Devices tracked:     "
        f"{len(history['devices'])}"
    )

    print(
        f"New devices:         "
        f"{new_devices}"
    )

    print(
        f"Devices moved:       "
        f"{moved_devices}"
    )

    print(
        f"MAC changes:         "
        f"{changed_mac_devices}"
    )

    print(
        f"IP changes:          "
        f"{changed_ip_devices}"
    )

    print()

    print(
        "============ NETWORK EVENTS ============"
    )

    print()

    if not events:

        print(
            "No changes detected."
        )

    else:

        for event in events:

            if event.get("event") == "DEVICE_MOVED":

                print(
                    "DEVICE MOVED"
                )

                print(
                    f"  Device:     "
                    f"{event.get('device_id', 'Unknown')}"
                )

                print(
                    f"  Type:       "
                    f"{event.get('device_type', 'UNKNOWN')}"
                )

                print(
                    f"  Vendor:     "
                    f"{event.get('vendor', 'Unknown')}"
                )

                print(
                    f"  From:       "
                    f"{event.get('from_port', 'Unknown')}"
                )

                print(
                    f"  To:         "
                    f"{event.get('to_port', 'Unknown')}"
                )

                print(
                    f"  IP:         "
                    f"{event.get('ip', 'Unknown')}"
                )

                print()

    print()

    for device_id in sorted(
        history["devices"]
    ):

        device = history[
            "devices"
        ][device_id]

        current = device.get(
            "current",
            {},
        )

        historical = device.get(
            "history",
            {},
        )

        print(
            f"DEVICE: {device_id}"
        )

        print(
            f"  First seen: "
            f"{device.get('first_seen', 'Unknown')}"
        )

        print(
            f"  Last seen:  "
            f"{device.get('last_seen', 'Unknown')}"
        )

        print(
            f"  Observations: "
            f"{device.get('observations', 0)}"
        )

        print(
            f"  Current port: "
            f"{current.get('port', 'Unknown')}"
        )

        print(
            f"  Current IP:   "
            f"{current.get('ip', 'Unknown')}"
        )

        print(
            f"  Current type: "
            f"{current.get('device_type', 'UNKNOWN')}"
        )

        print(
            "  Previous ports:"
        )

        previous_ports = historical.get(
            "previous_ports",
            [],
        )

        if previous_ports:

            for port in previous_ports:
                print(
                    f"    {port}"
                )

        else:
            print(
                "    None"
            )

        print(
            "  Previous MACs:"
        )

        previous_macs = historical.get(
            "previous_macs",
            [],
        )

        if previous_macs:

            for mac in previous_macs:
                print(
                    f"    {mac}"
                )

        else:
            print(
                "    None"
            )

        print(
            "  Previous IPs:"
        )

        previous_ips = historical.get(
            "previous_ips",
            [],
        )

        if previous_ips:

            for ip in previous_ips:
                print(
                    f"    {ip}"
                )

        else:
            print(
                "    None"
            )

        print(
            "-" * 50
        )


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Nexus persistent device history"
        )
    )

    parser.add_argument(
        "inventory",
        help="Nexus inventory JSON",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Print device history as JSON",
    )

    args = parser.parse_args()

    inventory_path = Path(
        args.inventory
    )

    if not inventory_path.exists():

        raise SystemExit(
            f"ERROR: Inventory not found: "
            f"{inventory_path}"
        )

    try:

        with inventory_path.open("r") as file:
            inventory = json.load(file)

    except json.JSONDecodeError as error:

        raise SystemExit(
            f"ERROR: Invalid inventory JSON: "
            f"{error}"
        )

    (
        history,
        new_devices,
        moved_devices,
        changed_mac_devices,
        changed_ip_devices,
        events,
    ) = update_device_history(
        inventory
    )

    if args.json:

        print(
            json.dumps(
                history,
                indent=2,
            )
        )

        return

    print_history_summary(
        history,
        new_devices,
        moved_devices,
        changed_mac_devices,
        changed_ip_devices,
        events,
    )

if __name__ == "__main__":
    main()

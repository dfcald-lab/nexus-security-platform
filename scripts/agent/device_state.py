#!/usr/bin/env python3

import json
import sys


def build_device_state(data):
    devices = []

    for device_id, device in data.get("devices", {}).items():

        state = {
            "device_id": device_id,
            "identity": {
                "type": device.get(
                    "device_type",
                    "UNKNOWN",
                ),
                "vendor": device.get(
                    "vendor",
                    "Unknown",
                ),
                "confidence": device.get(
                    "confidence",
                    "LOW",
                ),
            },
            "location": {
                "port": device.get(
                    "port",
                    "Unknown",
                ),
                "vlan": device.get(
                    "vlan",
                    "Unknown",
                ),
            },
            "addressing": {
                "ip": device.get(
                    "ip",
                    "Unknown",
                ),
                "ip_addresses": device.get(
                    "ip_addresses",
                    [],
                ),
            },
            "interfaces": {
                "mac_addresses": device.get(
                    "mac_addresses",
                    [],
                ),
            },
        }

        devices.append(state)

    return devices


def print_device_state(devices):
    print("=== NEXUS DEVICE STATE ===")
    print()

    if not devices:
        print("No logical devices discovered.")
        return

    print(f"Logical devices: {len(devices)}")
    print()

    for device in devices:

        identity = device["identity"]
        location = device["location"]
        addressing = device["addressing"]
        interfaces = device["interfaces"]

        print("DEVICE")
        print(f"  ID:          {device['device_id']}")
        print(f"  Type:        {identity['type']}")
        print(f"  Vendor:      {identity['vendor']}")
        print(f"  Confidence:  {identity['confidence']}")
        print()

        print("  LOCATION")
        print(f"    Port:      {location['port']}")
        print(f"    VLAN:      {location['vlan']}")
        print()

        print("  ADDRESSING")
        print(f"    IP:        {addressing['ip']}")
        print(
            f"    IP count:  "
            f"{len(addressing['ip_addresses'])}"
        )

        for ip in addressing["ip_addresses"]:
            print(f"      {ip}")

        print()

        print("  INTERFACES")
        print(
            f"    MAC count: "
            f"{len(interfaces['mac_addresses'])}"
        )

        for mac in interfaces["mac_addresses"]:
            print(f"      {mac}")

        print()
        print("-" * 50)
        print()


def main():
    if len(sys.argv) != 2:
        print(
            f"Usage: {sys.argv[0]} <inventory.json>"
        )
        sys.exit(1)

    inventory_file = sys.argv[1]

    with open(inventory_file) as f:
        data = json.load(f)

    devices = build_device_state(data)

    print_device_state(devices)


if __name__ == "__main__":
    main()

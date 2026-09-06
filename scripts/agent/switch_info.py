#!/usr/bin/env python3

import getpass
import json
import os
import pexpect
import sys

from scripts.agent.switch_parser import parse_switch
from scripts.agent.device_history import update_device_history

# ============================================================
# NEXUS SWITCH INTELLIGENCE AGENT
# ============================================================

COMMANDS = [
    "show version",
    "show ip interface brief",
    "show interfaces status",
    "show interfaces description",
    "show interfaces counters errors",
    "show interfaces switchport",
    "show vlan brief",
    "show ip route",
    "show mac address-table dynamic",
    "show ip arp",
    "show cdp neighbors",
    "show spanning-tree",
]


# ============================================================
# SSH SESSION
# ============================================================

class SwitchSession:

    def __init__(self, password):
        self.password = password
        self.child = None

    def connect(self):

        print(
            "Opening SSH connection to switch...",
            file=sys.stderr,
        )

        self.child = pexpect.spawn(
            "ssh",
            [
                "-o", "ControlMaster=no",
                "-o", "ControlPath=none",
                "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=10",
                "nexus-switch",
            ],
            encoding="utf-8",
            timeout=15,
        )

        try:

            self.child.expect(
                r"[Pp]assword:"
            )

            self.child.sendline(
                self.password
            )

            self.child.expect(
                r"Switch[#>]"
            )

            self.child.sendline(
                "terminal length 0"
            )

            self.child.expect(
                r"Switch[#>]"
            )

            print(
                "SSH connection established.",
                file=sys.stderr,
            )

        except pexpect.TIMEOUT:

            print(
                "ERROR: SSH connection timed out.",
                file=sys.stderr,
            )

            if self.child.before:
                print(
                    self.child.before,
                    file=sys.stderr,
                )

            self.close()

            return False

        except pexpect.EOF:

            print(
                "ERROR: SSH connection closed unexpectedly.",
                file=sys.stderr,
            )

            self.close()

            return False

        return True

    def run_command(self, command):

        if self.child is None:
            return ""

        try:

            self.child.sendline(
                command
            )

            self.child.expect(
                r"Switch[#>]"
            )

            output = self.child.before

            lines = output.splitlines()

            if lines:

                if lines[0].strip() == command:
                    lines = lines[1:]

            return "\n".join(
                lines
            ).strip()

        except pexpect.TIMEOUT:

            print(
                f"ERROR: command timed out: {command}",
                file=sys.stderr,
            )

            if self.child.before:
                print(
                    self.child.before,
                    file=sys.stderr,
                )

            return ""

        except pexpect.EOF:

            print(
                f"ERROR: SSH session closed during: {command}",
                file=sys.stderr,
            )

            return ""

    def close(self):

        if self.child is not None:

            try:

                self.child.sendline(
                    "exit"
                )

                self.child.close(
                    force=True
                )

            except Exception:
                pass

            self.child = None


# ============================================================
# COLLECT RAW SWITCH DATA
# ============================================================

def collect_switch_data(password):

    session = SwitchSession(
        password
    )

    if not session.connect():
        return {}

    data = {}

    try:

        for command in COMMANDS:

            print(
                f"Collecting: {command}",
                file=sys.stderr,
            )

            data[command] = (
                session.run_command(
                    command
                )
            )

    finally:

        session.close()

    return data


# ============================================================
# SERIALIZATION
# ============================================================

def serialize(value):

    if hasattr(
        value,
        "__dataclass_fields__",
    ):

        return {
            key: serialize(
                getattr(
                    value,
                    key,
                )
            )
            for key in value.__dataclass_fields__
        }

    if isinstance(
        value,
        dict,
    ):

        return {
            str(key): serialize(item)
            for key, item in value.items()
        }

    if isinstance(
        value,
        list,
    ):

        return [
            serialize(item)
            for item in value
        ]

    if isinstance(
        value,
        tuple,
    ):

        return [
            serialize(item)
            for item in value
        ]

    return value


# ============================================================
# JSON INVENTORY
# ============================================================

def build_inventory(switch):

    ports = {
        port.name: {
            "name": port.description,
            "status": port.status,
            "vlan": port.vlan,
            "duplex": port.duplex,
            "speed": port.speed,
            "mac_count": port.mac_count,
        }
        for port in switch.ports
    }

    # Populate MAC counts.
    mac_counts = {}

    for mac in switch.mac_addresses:

        mac_counts[mac.port] = (
            mac_counts.get(
                mac.port,
                0,
            )
            + 1
        )

    for port_name in ports:

        ports[port_name]["mac_count"] = (
            mac_counts.get(
                port_name,
                0,
            )
        )

    # MAC addresses grouped by switch port.
    mac_table = {}

    for mac in switch.mac_addresses:

        mac_table.setdefault(
            mac.port,
            [],
        ).append(
            mac.address
        )

    # Logical devices.
    devices = {}

    for device in switch.devices:

        devices[device.device_id] = {
            "device_id": device.device_id,
            "mac": device.mac,
            "port": device.port,
            "ip": device.ip,
	    "ip_addresses":device.ip_addresses,
            "vlan": device.vlan,
            "description": device.description,
            "device_type": device.device_type,
            "confidence": device.confidence,
            "vendor": device.vendor,
            "mac_addresses": device.mac_addresses,
        }

    # Port health.
    port_health = {}

    for port, error in switch.port_health.items():

        port_health[port] = {
            "align": error.align,
            "fcs": error.fcs,
            "tx": error.tx,
            "rx": error.rx,
            "undersize": error.undersize,
            "discard": error.discard,
        }

    descriptions = [
        {
            "interface": item.interface,
            "status": item.status,
            "protocol": item.protocol,
            "description": item.description,
        }
        for item in switch.descriptions
    ]

    switchports = {
        name: configuration.configuration
        for name, configuration
        in switch.switchports.items()
    }

    vlans = {
        vlan.vlan_id: {
            "name": vlan.name,
            "status": vlan.status,
            "ports": vlan.ports,
        }
        for vlan in switch.vlans
    }

    arp = [
        {
            "ip": entry.ip,
            "mac": entry.mac,
            "interface": entry.interface,
            "age": entry.age,
        }
        for entry in switch.arp_entries
    ]

    interfaces = [
        {
            "interface": interface.name,
            "ip": interface.ip,
            "status": interface.status,
            "protocol": interface.protocol,
        }
        for interface in switch.interfaces
    ]

    return {
        "switch": {
            "hostname": switch.hostname,
            "model": switch.model,
            "ios": switch.ios,
            "serial": switch.serial,
            "uptime": switch.uptime,
        },

        "interfaces": interfaces,

        "ports": ports,

        "port_health": port_health,

        "descriptions": descriptions,

        "switchports": switchports,

        "mac_addresses": mac_table,

        "arp": arp,

        "devices": devices,

        "vlans": vlans,

        "default_gateway": switch.default_gateway,

        "cdp_neighbors": switch.cdp_neighbors,

        "spanning_tree": {
            "root_priority": switch.spanning_tree.root_priority,
            "root_mac": switch.spanning_tree.root_mac,
            "bridge_priority": switch.spanning_tree.bridge_priority,
            "bridge_mac": switch.spanning_tree.bridge_mac,
            "role": switch.spanning_tree.role,
        },

        "health": {
            "interfaces_tracked": switch.health.interfaces_tracked,
            "connected_interfaces": switch.health.connected_interfaces,
            "connected_switch_ports": switch.health.connected_switch_ports,
            "learned_mac_addresses": switch.health.learned_mac_addresses,
            "arp_entries": switch.health.arp_entries,
            "devices_discovered": switch.health.devices_discovered,
            "vlans_discovered": switch.health.vlans_discovered,
            "cdp_neighbors": switch.health.cdp_neighbors,
            "port_errors": switch.health.port_errors,
            "overall": switch.health.overall,
        },
    }


# ============================================================
# HUMAN-READABLE REPORT
# ============================================================

def print_report(inventory):

    switch = inventory["switch"]
    health = inventory["health"]

    print()
    print("============ NEXUS SWITCH INTELLIGENCE ============")
    print()

    print(f"Hostname:        {switch['hostname']}")
    print(f"Model:           {switch['model']}")
    print(f"IOS:             {switch['ios']}")
    print(f"Serial:          {switch['serial']}")
    print(f"Uptime:          {switch['uptime']}")

    print()
    print("============ NETWORK HEALTH ============")
    print()

    print(f"Interfaces:      {health['interfaces_tracked']}")
    print(f"Connected:       {health['connected_interfaces']}")
    print(f"Switch ports:    {health['connected_switch_ports']}")
    print(f"MAC addresses:   {health['learned_mac_addresses']}")
    print(f"ARP entries:     {health['arp_entries']}")
    print(f"Devices:         {health['devices_discovered']}")
    print(f"VLANs:           {health['vlans_discovered']}")
    print(f"CDP neighbors:   {health['cdp_neighbors']}")
    print(f"Port errors:     {health['port_errors']}")
    print(f"Overall health:  {health['overall']}")

    print()
    print("============ DEVICE DISCOVERY ============")
    print()

    for mac, device in sorted(
        inventory["devices"].items()
    ):

        print(
            f"MAC={mac:<18} "
            f"IP={device['ip']:<16} "
            f"TYPE={device['device_type']:<15} "
            f"CONFIDENCE={device['confidence']:<6} "
            f"PORT={device['port']:<10} "
            f"VLAN={device['vlan']:<5} "
            f"DESC={device['description'] or '-'}"
        )

        child_macs = device.get(
            "mac_addresses",
            []
        )

        for child_mac in child_macs:
            print(f"    └── {child_mac}")

    print()
    print("============ SPANNING TREE ============")
    print()

    stp = inventory["spanning_tree"]

    print(f"Root priority:   {stp['root_priority']}")
    print(f"Root MAC:        {stp['root_mac']}")
    print(f"Bridge priority: {stp['bridge_priority']}")
    print(f"Bridge MAC:      {stp['bridge_mac']}")
    print(f"STP role:        {stp['role']}")

    print()
    print("====================================")

    events = inventory.get(
        "events",
        {},
    )

    print()
    print("============ NETWORK EVENTS ============")
    print()

    event_details = events.get(
        "details",
        [],
    )

    if not event_details:

        print("No changes detected.")

    else:

        for event in event_details:

            if event.get("event") == "DEVICE_MOVED":

                print()
                print("DEVICE MOVED")
                print(
                    f"  Device: {event.get('device_id', 'Unknown')}"
                )
                print(
                    f"  Type:   {event.get('device_type', 'UNKNOWN')}"
                )
                print(
                    f"  Vendor: {event.get('vendor', 'Unknown')}"
                )
                print(
                    f"  From:   {event.get('from_port', 'Unknown')}"
                )
                print(
                    f"  To:     {event.get('to_port', 'Unknown')}"
                )
                print(
                    f"  IP:     {event.get('ip', 'Unknown')}"
                )

# ============================================================
# MAIN
# ============================================================

def main():

    password = os.environ.get("NEXUS_SWITCH_PASSWORD")

    if not password:
        password = getpass.getpass(
            "Switch password: "
        )

    data = collect_switch_data(
        password
    )

    if not data:

        sys.exit(
            "ERROR: No switch data collected."
        )

    switch = parse_switch(
        data
    )

    inventory = build_inventory(
        switch
    )

    (
        device_history,
        new_devices,
        moved_devices,
        changed_mac_devices,
        changed_ip_devices,
        events,
    ) = update_device_history(
        inventory
    )

    inventory["events"] = {
        "new_devices": new_devices,
        "moved_devices": moved_devices,
        "changed_mac_devices": changed_mac_devices,
        "changed_ip_devices": changed_ip_devices,
        "details": events,
    }

    # ========================================================
    # APPLY PERSISTENT DEVICE IDENTITY
    # ========================================================
    #
    # The switch parser reports what the switch currently
    # says about a port.
    #
    # Device history contains what Nexus has learned about
    # the logical device over time.
    #
    # A port description can change when a device moves.
    # Persistent identity must therefore take precedence
    # over the current port description.
    #
    # Preserve the raw switch observations so Nexus does
    # not lose that evidence.
    # ========================================================

    for device_id, device in inventory.get(
        "devices",
        {},
    ).items():

        record = device_history.get(
            "devices",
            {},
        ).get(
            device_id
        )

        if not record:
            continue

        current = record.get(
            "current",
            {},
        )

        # Preserve what the switch currently reports.
        device["observed_description"] = device.get(
            "description",
            "",
        )

        device["observed_device_type"] = device.get(
            "device_type",
            "UNKNOWN",
        )

        # Apply persistent identity learned by Nexus.
        persistent_type = current.get(
            "device_type",
            "UNKNOWN",
        )

        persistent_vendor = current.get(
            "vendor",
            "Unknown",
        )

        persistent_description = current.get(
            "description",
            "",
        )

        if persistent_type and persistent_type != "UNKNOWN":
            device["device_type"] = persistent_type

        if persistent_vendor and persistent_vendor != "Unknown":
            device["vendor"] = persistent_vendor

        if persistent_description:
            device["identity_description"] = (
                persistent_description
            )

    if "--json" in sys.argv:

        print(
            json.dumps(
                inventory,
                indent=2,
                sort_keys=False,
            )
        )

        return

    print_report(
        inventory
    )


if __name__ == "__main__":
    main()

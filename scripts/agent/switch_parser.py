#!/usr/bin/env python3

import re
from collections import defaultdict

from .network_models import (
    ArpEntry,
    Device,
    Interface,
    InterfaceDescription,
    MacAddress,
    NetworkHealth,
    Port,
    PortError,
    SpanningTree,
    Switch,
    Switchport,
    Vlan,
)


# ============================================================
# HELPERS
# ============================================================

def find_value(text, pattern, default="Unknown"):
    match = re.search(
        pattern,
        text,
        re.IGNORECASE | re.MULTILINE,
    )

    if match:
        return match.group(1).strip()

    return default


def normalize_mac(mac):
    return (
        mac.lower()
        .replace(".", "")
        .replace(":", "")
        .replace("-", "")
    )


# ============================================================
# DEVICE CLASSIFICATION
# ============================================================

def classify_device(description):
    """
    Classify a device using the switch port description.

    Port descriptions are treated as strong evidence because
    they are explicitly assigned to the physical switch port.

    Returns:
        (device_type, confidence)
    """

    if not description:
        return "UNKNOWN", "LOW"

    value = description.strip().lower()

    classification_rules = [
        (
            "STEAM-DECK",
            (
                "steam-deck",
                "steam deck",
                "steamdeck",
            ),
            "HIGH",
        ),
        (
            "PRINTER",
            (
                "printer",
                "print",
            ),
            "HIGH",
        ),
        (
            "CAMERA",
            (
                "camera",
                "cam",
                "cctv",
            ),
            "HIGH",
        ),
        (
            "ACCESS-POINT",
            (
                "access-point",
                "access point",
                "wifi-ap",
                "wireless-ap",
                "wireless",
            ),
            "HIGH",
        ),
        (
            "SWITCH",
            (
                "switch",
                "network-switch",
            ),
            "HIGH",
        ),
        (
            "ROUTER",
            (
                "router",
                "gateway",
            ),
            "HIGH",
        ),
        (
            "SERVER",
            (
                "server",
                "srv",
            ),
            "HIGH",
        ),
        (
            "NAS",
            (
                "nas",
                "storage",
            ),
            "HIGH",
        ),
        (
            "TELEVISION",
            (
                "tv",
                "television",
                "smart-tv",
                "smart tv",
            ),
            "HIGH",
        ),
        (
            "DESKTOP",
            (
                "desktop",
                "pc",
                "workstation",
            ),
            "HIGH",
        ),
        (
            "LAPTOP",
            (
                "laptop",
                "notebook",
            ),
            "HIGH",
        ),
        (
            "PHONE",
            (
                "phone",
                "iphone",
                "android",
            ),
            "HIGH",
        ),
    ]

    for device_type, keywords, confidence in classification_rules:

        for keyword in keywords:

            if keyword in value:
                return device_type, confidence

    return "UNKNOWN", "LOW"


# ============================================================
# SWITCH SUMMARY
# ============================================================

def parse_switch_summary(version):
    switch = Switch()

    uptime_match = re.search(
        r"^(\S+)\s+uptime is\s+(.+)$",
        version,
        re.MULTILINE,
    )

    if uptime_match:
        switch.hostname = uptime_match.group(1)
        switch.uptime = uptime_match.group(2).strip()

    switch.model = find_value(
        version,
        r"^Model number\s+:\s+(.+)$",
    )

    switch.ios = find_value(
        version,
        r"Cisco IOS Software.*?Version\s+([^,\s]+)",
    )

    switch.serial = find_value(
        version,
        r"^System serial number\s+:\s+(.+)$",
    )

    return switch


# ============================================================
# INTERFACES
# ============================================================

def parse_interfaces(text):
    interfaces = []

    for line in text.splitlines():

        parts = line.split()

        if len(parts) < 6:
            continue

        if parts[0].lower() == "interface":
            continue

        interface = parts[0]
        ip = parts[1]
        status = parts[-2]
        protocol = parts[-1]

        if re.match(
            r"^(FastEthernet|GigabitEthernet|"
            r"TenGigabitEthernet|Vlan|Port-channel)",
            interface,
            re.IGNORECASE,
        ):
            interfaces.append(
                Interface(
                    name=interface,
                    ip=ip,
                    status=status,
                    protocol=protocol,
                )
            )

    return interfaces


# ============================================================
# PORT STATUS
# ============================================================

def parse_ports(text):
    ports = []

    for line in text.splitlines():

        parts = line.split()

        if len(parts) < 5:
            continue

        if parts[0].lower() == "port":
            continue

        port = parts[0]

        if not re.match(
            r"^(Fa|Gi|Te|Po)",
            port,
            re.IGNORECASE,
        ):
            continue

        status_index = None

        for index, value in enumerate(parts):

            if value.lower() in (
                "connected",
                "notconnect",
                "disabled",
                "err-disabled",
            ):
                status_index = index
                break

        if status_index is None:
            continue

        status = parts[status_index]

        vlan = (
            parts[status_index + 1]
            if len(parts) > status_index + 1
            else "?"
        )

        duplex = (
            parts[status_index + 2]
            if len(parts) > status_index + 2
            else "?"
        )

        speed = (
            parts[status_index + 3]
            if len(parts) > status_index + 3
            else "?"
        )

        description = ""

        if status_index > 1:
            description = " ".join(
                parts[1:status_index]
            )

        ports.append(
            Port(
                name=port,
                status=status,
                vlan=vlan,
                duplex=duplex,
                speed=speed,
                description=description,
            )
        )

    return ports


# ============================================================
# PORT HEALTH
# ============================================================

def parse_port_health(text):
    errors = {}

    for line in text.splitlines():

        parts = line.split()

        if len(parts) < 7:
            continue

        if parts[0].lower() == "port":
            continue

        port = parts[0]

        if not re.match(
            r"^(Fa|Gi|Te|Po)",
            port,
            re.IGNORECASE,
        ):
            continue

        try:

            align_errors = int(parts[1])
            fcs_errors = int(parts[2])
            transmit_errors = int(parts[3])
            receive_errors = int(parts[4])
            undersize = int(parts[5])
            out_discards = int(parts[6])

        except ValueError:
            continue

        errors[port] = PortError(
            align=align_errors,
            fcs=fcs_errors,
            tx=transmit_errors,
            rx=receive_errors,
            undersize=undersize,
            discard=out_discards,
        )

    return errors


# ============================================================
# INTERFACE DESCRIPTIONS
# ============================================================

def parse_descriptions(text):
    descriptions = []

    for line in text.splitlines():

        parts = line.split()

        if len(parts) < 3:
            continue

        if parts[0].lower() == "interface":
            continue

        interface = parts[0]
        status = parts[1]
        protocol = parts[2]

        description = (
            " ".join(parts[3:])
            if len(parts) > 3
            else ""
        )

        if description:
            descriptions.append(
                InterfaceDescription(
                    interface=interface,
                    status=status,
                    protocol=protocol,
                    description=description,
                )
            )

    return descriptions


# ============================================================
# SWITCHPORT CONFIGURATION
# ============================================================

def parse_switchports(text):
    switchports = {}
    current_port = None

    for line in text.splitlines():

        if line.startswith("Name: "):

            current_port = line.split(
                "Name:",
                1,
            )[1].strip()

            switchports[current_port] = Switchport(
                name=current_port
            )

            continue

        if current_port is None:
            continue

        if ":" not in line:
            continue

        key, value = line.split(
            ":",
            1,
        )

        switchports[current_port].configuration[
            key.strip()
        ] = value.strip()

    return switchports


# ============================================================
# MAC TABLE
# ============================================================

def parse_macs(text):
    mac_addresses = []

    for line in text.splitlines():

        match = re.match(
            r"\s*(\d+)\s+([0-9a-f.:-]+)\s+\S+\s+(\S+)",
            line,
            re.IGNORECASE,
        )

        if match:

            _, mac, port = match.groups()

            mac_addresses.append(
                MacAddress(
                    address=mac,
                    port=port,
                )
            )

    return mac_addresses


# ============================================================
# ARP
# ============================================================

def parse_arp(text):
    arp_entries = []

    for line in text.splitlines():

        parts = line.split()

        if len(parts) < 6:
            continue

        if parts[0].lower() == "protocol":
            continue

        arp_entries.append(
            ArpEntry(
                ip=parts[1],
                age=parts[2],
                mac=parts[3],
                interface=parts[5],
            )
        )

    return arp_entries


# ============================================================
# VLAN
# ============================================================

def parse_vlans(text):
    vlans = []
    current_vlan = None

    for line in text.splitlines():

        match = re.match(
            r"^(\d+)\s+(\S+)\s+(\S+)\s*(.*)$",
            line,
        )

        if match:

            vlan_id, name, status, ports = match.groups()

            current_vlan = vlan_id

            vlans.append(
                Vlan(
                    vlan_id=vlan_id,
                    name=name,
                    status=status,
                    ports=[
                        port.strip()
                        for port in ports.split(",")
                        if port.strip()
                    ],
                )
            )

        elif (
            current_vlan
            and line.startswith((" ", "\t"))
            and line.strip()
        ):

            for vlan in vlans:

                if vlan.vlan_id == current_vlan:

                    vlan.ports.extend(
                        port.strip()
                        for port in line.split(",")
                        if port.strip()
                    )

                    break

    return vlans


# ============================================================
# ROUTING
# ============================================================

def parse_routes(text):
    return find_value(
        text,
        r"Default gateway is\s+(\S+)",
        "None",
    )


# ============================================================
# CDP
# ============================================================

def parse_cdp(text):
    neighbors = []

    for line in text.splitlines():

        if not line.strip():
            continue

        if line.startswith(
            (
                "Capability Codes",
                "Device ID",
                "----",
                "Capability",
            )
        ):
            continue

        if "Source Route Bridge" in line:
            continue

        if line.strip().startswith(
            (
                "S -",
                "D -",
                "B -",
                "C -",
                "M -",
            )
        ):
            continue

        parts = line.split()

        if len(parts) >= 6:
            neighbors.append(line.strip())

    return neighbors


# ============================================================
# SPANNING TREE
# ============================================================

def parse_spanning_tree(text):
    root_priority = find_value(
        text,
        r"Root ID\s+Priority\s+(\d+)",
    )

    bridge_priority = find_value(
        text,
        r"Bridge ID\s+Priority\s+(\d+)",
    )

    root_mac_match = re.search(
        r"Root ID.*?"
        r"Address\s+([0-9a-f.]+)",
        text,
        re.IGNORECASE | re.DOTALL,
    )

    bridge_mac_match = re.search(
        r"Bridge ID.*?"
        r"Address\s+([0-9a-f.]+)",
        text,
        re.IGNORECASE | re.DOTALL,
    )

    root_mac = (
        root_mac_match.group(1)
        if root_mac_match
        else "Unknown"
    )

    bridge_mac = (
        bridge_mac_match.group(1)
        if bridge_mac_match
        else "Unknown"
    )

    if (
        root_mac != "Unknown"
        and bridge_mac != "Unknown"
    ):

        if normalize_mac(root_mac) == normalize_mac(
            bridge_mac
        ):
            role = "ROOT BRIDGE"
        else:
            role = "NON-ROOT BRIDGE"

    else:
        role = "UNKNOWN"

    return SpanningTree(
        root_priority=root_priority,
        root_mac=root_mac,
        bridge_priority=bridge_priority,
        bridge_mac=bridge_mac,
        role=role,
    )

# ============================================================
# DEVICE DISCOVERY
# ============================================================

def build_devices(
    mac_addresses,
    arp_entries,
    ports,
):
    devices = {}

    port_lookup = {
        port.name: port
        for port in ports
    }

    # Build a MAC -> IP lookup from ARP.
    arp_by_mac = {}

    for arp_entry in arp_entries:

        normalized_mac = normalize_mac(
            arp_entry.mac
        )

        if normalized_mac:
            arp_by_mac[normalized_mac] = arp_entry.ip

    # Group observed MAC addresses by physical
    # switch port first.
    #
    # A switch port is a physical location.
    # It is NOT the logical device identity.
    port_macs = {}

    for mac_entry in mac_addresses:

        port_macs.setdefault(
            mac_entry.port,
            [],
        ).append(
            mac_entry.address
        )

    # Create one logical device for each occupied
    # switch port.
    #
    # The primary identity is the MAC address that
    # has an ARP/IP association. If no MAC has an
    # ARP entry, fall back to the first observed MAC.
    #
    # All observed MAC addresses remain attached to
    # the logical device.
    for port_name, macs in port_macs.items():

        port = port_lookup.get(
            port_name
        )

        description = (
            port.description
            if port
            else ""
        )

        device_type, confidence = classify_device(
            description
        )

        primary_mac = None
        primary_ip = "Unknown"

        # Prefer an observed MAC with an ARP entry.
        for mac in macs:

            normalized_mac = normalize_mac(
                mac
            )

            if normalized_mac in arp_by_mac:

                primary_mac = mac
                primary_ip = arp_by_mac[
                    normalized_mac
                ]

                break

        # If no ARP-associated MAC exists,
        # use the first observed MAC.
        if primary_mac is None:

            primary_mac = macs[0]

        device_id = primary_mac

        devices[device_id] = Device(
            device_id=device_id,
            mac=primary_mac,
            ip=primary_ip,
            port=port_name,
            vlan=(
                port.vlan
                if port
                else "Unknown"
            ),
            description=description,
            device_type=device_type,
            confidence=confidence,
            vendor=(
                "Valve"
                if device_type == "STEAM-DECK"
                else "Unknown"
            ),
            mac_addresses=list(macs),
            ip_addresses=[],
        )

        # Associate every ARP-discovered IP with
        # this logical device.
        for mac in macs:

            normalized_mac = normalize_mac(
                mac
            )

            ip = arp_by_mac.get(
                normalized_mac
            )

            if (
                ip
                and ip not in devices[device_id].ip_addresses
            ):

                devices[
                    device_id
                ].ip_addresses.append(
                    ip
                )

        # Preserve the primary IP in the complete
        # IP inventory.
        if (
            primary_ip != "Unknown"
            and primary_ip
            not in devices[device_id].ip_addresses
        ):

            devices[
                device_id
            ].ip_addresses.append(
                primary_ip
            )

    return list(devices.values())

# ============================================================


def build_health(
    interfaces,
    ports,
    mac_addresses,
    arp_entries,
    devices,
    vlans,
    cdp_neighbors,
    port_health,
):

    problem_ports = sum(
        1
        for error in port_health.values()
        if error.total > 0
    )

    connected_interfaces = sum(
        1
        for interface in interfaces
        if interface.status.lower() == "up"
        and interface.protocol.lower() == "up"
    )

    connected_switch_ports = sum(
        1
        for port in ports
        if port.status.lower() == "connected"
    )

    if problem_ports > 0:
        overall = "DEGRADED"
    else:
        overall = "HEALTHY"

    return NetworkHealth(
        interfaces_tracked=len(interfaces),
        connected_interfaces=connected_interfaces,
        connected_switch_ports=connected_switch_ports,
        learned_mac_addresses=len(mac_addresses),
        arp_entries=len(arp_entries),
        devices_discovered=len(devices),
        vlans_discovered=len(vlans),
        cdp_neighbors=len(cdp_neighbors),
        port_errors=problem_ports,
        overall=overall,
    )


def parse_switch(data):

    switch = Switch()

    summary = parse_switch_summary(
        data.get("show version", "")
    )

    switch.hostname = summary.hostname
    switch.model = summary.model
    switch.ios = summary.ios
    switch.serial = summary.serial
    switch.uptime = summary.uptime
    switch.interfaces = parse_interfaces(
        data.get("show ip interface brief", "")
    )

    switch.ports = parse_ports(
        data.get(
            "show interfaces status",
            "",
        )
    )

    switch.port_health = parse_port_health(
        data.get(
            "show interfaces counters errors",
            "",
        )
    )

    switch.descriptions = parse_descriptions(
        data.get(
            "show interfaces description",
            "",
        )
    )

    switch.switchports = parse_switchports(
        data.get(
            "show interfaces switchport",
            "",
        )
    )

    switch.mac_addresses = parse_macs(
        data.get(
            "show mac address-table dynamic",
            "",
        )
    )

    switch.arp_entries = parse_arp(
        data.get(
            "show ip arp",
            "",
        )
    )

    switch.devices = build_devices(
        switch.mac_addresses,
        switch.arp_entries,
        switch.ports,
    )

    switch.vlans = parse_vlans(
        data.get(
            "show vlan brief",
            "",
        )
    )

    switch.default_gateway = parse_routes(
        data.get(
            "show ip route",
            "",
        )
    )

    switch.cdp_neighbors = parse_cdp(
        data.get(
            "show cdp neighbors",
            "",
        )
    )

    switch.spanning_tree = parse_spanning_tree(
        data.get(
            "show spanning-tree",
            "",
        )
    )

    switch.health = build_health(
        switch.interfaces,
        switch.ports,
        switch.mac_addresses,
        switch.arp_entries,
        switch.devices,
        switch.vlans,
        switch.cdp_neighbors,
        switch.port_health,
    )

    return switch

#!/usr/bin/env python3

import argparse
import json
from pathlib import Path


# ============================================================
# NEXUS NETWORK TOPOLOGY
# ============================================================

TOPOLOGY_DIR = (
    Path.home()
    / "nexus"
    / "monitoring"
    / "topology"
)

TOPOLOGY_FILE = TOPOLOGY_DIR / "current.json"

JETSON_IDENTITY_FILE = (
    Path.home()
    / "nexus"
    / "monitoring"
    / "endpoints"
    / "jetson.json"
)


# ============================================================
# HELPERS
# ============================================================

def normalize_mac(mac):
    return (
        mac.lower()
        .replace(".", "")
        .replace(":", "")
        .replace("-", "")
    )


def build_arp_map(arp_entries):
    result = {}

    for entry in arp_entries:
        if not isinstance(entry, dict):
            continue

        mac = normalize_mac(
            entry.get("mac", "")
        )

        ip = entry.get(
            "ip",
            "Unknown",
        )

        if mac:
            result[mac] = ip

    return result


def build_device_map(devices):
    result = {}

    if not isinstance(devices, dict):
        return result

    for device_id, device in devices.items():
        if isinstance(device, dict):
            result[device_id] = device

    return result


def classify_port(port, observed_macs):
    status = port.get(
        "status",
        "unknown",
    ).lower()

    if status != "connected":
        return "DISCONNECTED"

    if len(observed_macs) == 0:
        return "CONNECTED_UNKNOWN"

    if len(observed_macs) == 1:
        return "DIRECT_DEVICE"

    return "MULTI_MAC"


# ============================================================
# JETSON ENDPOINT EVIDENCE
# ============================================================

def load_jetson_identity(path=None):
    if path is None:
        path = JETSON_IDENTITY_FILE

    if not path.exists():
        return None

    try:
        with path.open("r") as file:
            data = json.load(file)
    except (
        json.JSONDecodeError,
        OSError,
    ):
        return None

    if not isinstance(data, dict):
        return None

    return data


def correlate_endpoint(endpoint, jetson):
    if not jetson:
        return endpoint

    endpoint_mac = normalize_mac(
        endpoint.get("mac", "")
    )

    jetson_mac = normalize_mac(
        jetson.get("mac", "")
    )

    if (
        not endpoint_mac
        or not jetson_mac
        or endpoint_mac != jetson_mac
    ):
        return endpoint

    jetson_ip = (
        jetson.get(
            "ipv4",
            "",
        )
        .split("/", 1)[0]
    )

    endpoint["device_id"] = (
        "jetson:"
        + jetson.get(
            "hostname",
            "yahboom",
        )
    )

    endpoint["device_type"] = "JETSON"
    endpoint["vendor"] = "NVIDIA"
    endpoint["hostname"] = jetson.get(
        "hostname",
        "yahboom",
    )
    endpoint["os"] = jetson.get(
        "os",
        "Unknown",
    )

    if (
        endpoint.get("ip", "Unknown") == "Unknown"
        and jetson_ip
    ):
        endpoint["ip"] = jetson_ip

    endpoint["endpoint_evidence"] = {
        "transport": "ssh",
        "host": jetson.get(
            "source",
            {},
        ).get(
            "host",
            jetson_ip,
        ),
        "evidence": "jetson_endpoint",
        "confidence": "HIGH",
    }

    return endpoint


# ============================================================
# PORT TOPOLOGY
# ============================================================

def build_port_topology(
    ports,
    mac_table,
    devices,
    arp_map,
    descriptions,
    jetson=None,
):
    topology_ports = []

    device_map = build_device_map(
        devices
    )

    description_map = {}

    for item in descriptions:
        if not isinstance(item, dict):
            continue

        interface = item.get(
            "interface",
            "",
        )

        if interface:
            description_map[interface] = item.get(
                "description",
                "",
            )

    for port_name, port in sorted(
        ports.items()
    ):
        if not isinstance(port, dict):
            continue

        observed_macs = list(
            mac_table.get(
                port_name,
                [],
            )
        )

        normalized_macs = [
            normalize_mac(mac)
            for mac in observed_macs
            if mac
        ]

        endpoint_records = []

        for mac in observed_macs:
            normalized_mac = normalize_mac(mac)

            ip = arp_map.get(
                normalized_mac,
                "Unknown",
            )

            matched_device = None
            association = "OBSERVED_MAC"

            for candidate in device_map.values():
                candidate_mac = normalize_mac(
                    candidate.get(
                        "mac",
                        "",
                    )
                )

                if candidate_mac == normalized_mac:
                    matched_device = candidate
                    association = "PRIMARY_DEVICE_MAC"
                    break

            endpoint = {
                "mac": mac,
                "ip": ip,
                "device_id": (
                    matched_device.get(
                        "device_id",
                        "UNKNOWN",
                    )
                    if matched_device
                    else "UNKNOWN"
                ),
                "device_type": (
                    matched_device.get(
                        "device_type",
                        "UNKNOWN",
                    )
                    if matched_device
                    else "UNKNOWN"
                ),
                "vendor": (
                    matched_device.get(
                        "vendor",
                        "Unknown",
                    )
                    if matched_device
                    else "Unknown"
                ),
                "association": association,
            }

            endpoint = correlate_endpoint(
                endpoint,
                jetson,
            )

            endpoint_records.append(
                endpoint
            )

        description = description_map.get(
            port_name,
            port.get(
                "description",
                "",
            ),
        )

        topology_ports.append(
            {
                "port": port_name,
                "status": port.get(
                    "status",
                    "unknown",
                ),
                "vlan": port.get(
                    "vlan",
                    "Unknown",
                ),
                "duplex": port.get(
                    "duplex",
                    "Unknown",
                ),
                "speed": port.get(
                    "speed",
                    "Unknown",
                ),
                "description": description,
                "mac_count": len(
                    normalized_macs
                ),
                "classification": classify_port(
                    port,
                    observed_macs,
                ),
                "observed_endpoints": endpoint_records,
            }
        )

    return topology_ports


# ============================================================
# TOPOLOGY NODES
# ============================================================

def build_nodes(
    switch,
    gateway,
    ports,
):
    nodes = {}

    switch_id = switch.get(
        "id",
        "UNKNOWN",
    )

    switch_node_id = (
        f"switch:{switch_id}"
    )

    nodes[switch_node_id] = {
        "id": switch_node_id,
        "type": "SWITCH",
        "hostname": switch.get(
            "hostname",
            "Unknown",
        ),
        "model": switch.get(
            "model",
            "Unknown",
        ),
        "management_ip": switch.get(
            "management_ip",
            "Unknown",
        ),
    }

    gateway_ip = gateway.get(
        "ip",
        "Unknown",
    )

    if gateway_ip != "Unknown":
        gateway_id = f"ip:{gateway_ip}"

        nodes[gateway_id] = {
            "id": gateway_id,
            "type": "GATEWAY",
            "ip": gateway_ip,
            "mac": gateway.get(
                "mac",
                "Unknown",
            ),
            "evidence": gateway.get(
                "evidence",
                "Unknown",
            ),
        }

    for port in ports:
        port_name = port.get(
            "port",
            "Unknown",
        )

        if port_name == "Unknown":
            continue

        port_id = (
            f"port:{port_name}"
        )

        nodes[port_id] = {
            "id": port_id,
            "type": "SWITCH_PORT",
            "port": port_name,
            "status": port.get(
                "status",
                "unknown",
            ),
            "vlan": port.get(
                "vlan",
                "Unknown",
            ),
            "description": port.get(
                "description",
                "",
            ),
            "classification": port.get(
                "classification",
                "UNKNOWN",
            ),
        }

        for endpoint in port.get(
            "observed_endpoints",
            [],
        ):
            mac = endpoint.get(
                "mac",
                "",
            )

            if not mac:
                continue

            mac_id = (
                f"mac:{normalize_mac(mac)}"
            )

            nodes[mac_id] = {
                "id": mac_id,
                "type": "MAC",
                "mac": mac,
                "ip": endpoint.get(
                    "ip",
                    "Unknown",
                ),
                "device_type": endpoint.get(
                    "device_type",
                    "UNKNOWN",
                ),
                "vendor": endpoint.get(
                    "vendor",
                    "Unknown",
                ),
                "association": endpoint.get(
                    "association",
                    "OBSERVED_MAC",
                ),
            }

            device_id = endpoint.get(
                "device_id",
                "UNKNOWN",
            )

            if device_id != "UNKNOWN":
                device_node_id = (
                    f"device:{device_id}"
                )

                if device_node_id not in nodes:
                    nodes[device_node_id] = {
                        "id": device_node_id,
                        "type": "DEVICE",
                        "device_id": device_id,
                        "device_type": endpoint.get(
                            "device_type",
                            "UNKNOWN",
                        ),
                        "vendor": endpoint.get(
                            "vendor",
                            "Unknown",
                        ),
                        "hostname": endpoint.get(
                            "hostname",
                            "",
                        ),
                        "os": endpoint.get(
                            "os",
                            "Unknown",
                        ),
                    }

            ip = endpoint.get(
                "ip",
                "Unknown",
            )

            if ip != "Unknown":
                ip_node_id = f"ip:{ip}"

                if ip_node_id not in nodes:
                    nodes[ip_node_id] = {
                        "id": ip_node_id,
                        "type": "IP",
                        "ip": ip,
                    }

    return nodes


# ============================================================
# TOPOLOGY EDGES
# ============================================================

def build_edges(
    switch_node,
    gateway_node,
    ports,
):
    edges = []

    switch_id = (
        f"switch:{switch_node['id']}"
    )

    gateway_ip = gateway_node.get(
        "ip",
        "Unknown",
    )

    if gateway_ip != "Unknown":
        edges.append(
            {
                "source": switch_id,
                "target": f"ip:{gateway_ip}",
                "type": "DEFAULT_ROUTE",
                "evidence": "switch_default_route",
                "confidence": "MEDIUM",
            }
        )

    for port in ports:
        port_name = port.get(
            "port",
            "Unknown",
        )

        if port_name == "Unknown":
            continue

        observed_endpoints = port.get(
            "observed_endpoints",
            [],
        )

        status = port.get(
            "status",
            "unknown",
        ).lower()

        if (
            status != "connected"
            and not observed_endpoints
        ):
            continue

        port_id = (
            f"port:{port_name}"
        )

        edges.append(
            {
                "source": switch_id,
                "target": port_id,
                "type": "SWITCH_PORT",
                "evidence": "switch_interface",
                "confidence": "HIGH",
            }
        )

        for endpoint in observed_endpoints:
            mac = endpoint.get(
                "mac",
                "",
            )

            if not mac:
                continue

            mac_id = (
                f"mac:{normalize_mac(mac)}"
            )

            edges.append(
                {
                    "source": port_id,
                    "target": mac_id,
                    "type": "MAC_OBSERVED",
                    "evidence": "switch_mac_table",
                    "confidence": "HIGH",
                    "association": endpoint.get(
                        "association",
                        "OBSERVED_MAC",
                    ),
                }
            )

            ip = endpoint.get(
                "ip",
                "Unknown",
            )

            if ip != "Unknown":
                edges.append(
                    {
                        "source": mac_id,
                        "target": f"ip:{ip}",
                        "type": "IP_CORRELATION",
                        "evidence": "switch_arp",
                        "confidence": "HIGH",
                    }
                )

            device_id = endpoint.get(
                "device_id",
                "UNKNOWN",
            )

            if device_id != "UNKNOWN":
                edges.append(
                    {
                        "source": mac_id,
                        "target": (
                            f"device:{device_id}"
                        ),
                        "type": "DEVICE_IDENTITY",
                        "evidence": (
                            endpoint.get(
                                "endpoint_evidence",
                                {},
                            ).get(
                                "evidence",
                                "persistent_device_identity",
                            )
                        ),
                        "confidence": (
                            endpoint.get(
                                "endpoint_evidence",
                                {},
                            ).get(
                                "confidence",
                                "HIGH",
                            )
                        ),
                    }
                )

    return edges


# ============================================================
# TOPOLOGY BUILD
# ============================================================

def build_topology(inventory):
    switch = inventory.get(
        "switch",
        {},
    )

    ports = inventory.get(
        "ports",
        {},
    )

    mac_table = inventory.get(
        "mac_addresses",
        {},
    )

    devices = inventory.get(
        "devices",
        {},
    )

    arp_entries = inventory.get(
        "arp",
        [],
    )

    descriptions = inventory.get(
        "descriptions",
        [],
    )

    default_gateway = inventory.get(
        "default_gateway",
        "Unknown",
    )

    management_ip = next(
        (
            interface.get("ip")
            for interface in inventory.get(
                "interfaces",
                [],
            )
            if interface.get(
                "interface",
                "",
            ).lower() == "vlan1"
            and interface.get("ip")
            and interface.get(
                "ip"
            ) != "unassigned"
        ),
        "Unknown",
    )

    jetson = load_jetson_identity()

    arp_map = build_arp_map(
        arp_entries
    )

    topology_ports = build_port_topology(
        ports,
        mac_table,
        devices,
        arp_map,
        descriptions,
        jetson,
    )

    switch_node = {
        "id": switch.get(
            "serial",
            switch.get(
                "hostname",
                "UNKNOWN",
            ),
        ),
        "hostname": switch.get(
            "hostname",
            "Unknown",
        ),
        "model": switch.get(
            "model",
            "Unknown",
        ),
        "management_ip": management_ip,
    }

    gateway_node = {
        "ip": default_gateway,
        "evidence": "switch_default_route",
        "mac": "Unknown",
    }

    nodes = build_nodes(
        switch_node,
        gateway_node,
        topology_ports,
    )

    edges = build_edges(
        switch_node,
        gateway_node,
        topology_ports,
    )

    return {
        "schema": "nexus.topology.v1",
        "switch": {
            "hostname": switch.get(
                "hostname",
                "Unknown",
            ),
            "model": switch.get(
                "model",
                "Unknown",
            ),
            "serial": switch.get(
                "serial",
                "Unknown",
            ),
            "management_ip": management_ip,
        },
        "default_gateway": {
            "ip": default_gateway,
            "evidence": "switch_default_route",
        },
        "nodes": nodes,
        "edges": edges,
        "ports": topology_ports,
        "summary": {
            "ports_total": len(
                topology_ports
            ),
            "direct_devices": sum(
                1
                for port in topology_ports
                if port["classification"]
                == "DIRECT_DEVICE"
            ),
            "multi_mac_ports": sum(
                1
                for port in topology_ports
                if port["classification"]
                == "MULTI_MAC"
            ),
            "connected_unknown": sum(
                1
                for port in topology_ports
                if port["classification"]
                == "CONNECTED_UNKNOWN"
            ),
            "disconnected": sum(
                1
                for port in topology_ports
                if port["classification"]
                == "DISCONNECTED"
            ),
            "edges": len(edges),
        },
    }


# ============================================================
# SAVE
# ============================================================

def save_topology(topology):
    TOPOLOGY_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary = TOPOLOGY_FILE.with_suffix(
        ".tmp"
    )

    with temporary.open("w") as file:
        json.dump(
            topology,
            file,
            indent=2,
        )

    temporary.replace(
        TOPOLOGY_FILE
    )


# ============================================================
# DISPLAY
# ============================================================

def print_topology(topology):
    switch = topology["switch"]

    print()
    print(
        "============ NEXUS NETWORK TOPOLOGY ============"
    )
    print()

    print(
        f"Switch:      {switch['hostname']}"
    )
    print(
        f"Model:       {switch['model']}"
    )
    print(
        f"Management:  {switch['management_ip']}"
    )
    print(
        f"Gateway:     {topology['default_gateway']['ip']}"
    )

    print()
    print(
        "============ NETWORK NODES ============"
    )
    print()

    switch_nodes = [
        node
        for node in topology["nodes"].values()
        if node.get("type") == "SWITCH"
    ]

    if switch_nodes:
        node = switch_nodes[0]

        print(
            f"SWITCH   ID={node['id']} "
            f"IP={node['management_ip']}"
        )

    gateway_ip = (
        topology["default_gateway"]["ip"]
    )

    gateway = topology["nodes"].get(
        f"ip:{gateway_ip}",
        {},
    )

    print(
        f"GATEWAY  IP={gateway.get('ip', gateway_ip)} "
        f"MAC={gateway.get('mac', 'Unknown')} "
        f"EVIDENCE={gateway.get('evidence', 'Unknown')}"
    )

    print()
    print(
        "============ PORT OBSERVATIONS ============"
    )
    print()

    for port in topology["ports"]:
        print(
            f"{port['port']:<10} "
            f"{port['classification']:<18} "
            f"VLAN={port['vlan']:<4} "
            f"MACs={port['mac_count']:<2} "
            f"DESC={port['description'] or '-'}"
        )

        for endpoint in port[
            "observed_endpoints"
        ]:
            print(
                f"    └── "
                f"MAC={endpoint['mac']} "
                f"IP={endpoint['ip']} "
                f"TYPE={endpoint['device_type']} "
                f"DEVICE={endpoint['device_id']}"
            )

            if endpoint.get("hostname"):
                print(
                    f"        HOSTNAME={endpoint['hostname']} "
                    f"OS={endpoint.get('os', 'Unknown')}"
                )

    print()
    print(
        "============ TOPOLOGY SUMMARY ============"
    )
    print()

    summary = topology["summary"]

    print(
        f"Ports total:          "
        f"{summary['ports_total']}"
    )
    print(
        f"Direct devices:       "
        f"{summary['direct_devices']}"
    )
    print(
        f"Multi-MAC ports:      "
        f"{summary['multi_mac_ports']}"
    )
    print(
        f"Connected unknown:    "
        f"{summary['connected_unknown']}"
    )
    print(
        f"Disconnected:         "
        f"{summary['disconnected']}"
    )
    print(
        f"Topology edges:       "
        f"{summary['edges']}"
    )
    print()


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Nexus network topology builder"
    )

    parser.add_argument(
        "inventory",
        help="Nexus inventory JSON",
    )

    parser.add_argument(
        "--save",
        action="store_true",
        help="Save topology to monitoring/topology",
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

    topology = build_topology(
        inventory
    )

    print_topology(
        topology
    )

    if args.save:
        save_topology(
            topology
        )

        print(
            f"Saved topology: "
            f"{TOPOLOGY_FILE}"
        )


if __name__ == "__main__":
    main()

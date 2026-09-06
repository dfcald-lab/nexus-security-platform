#!/usr/bin/env python3

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class Interface:
    name: str
    ip: str
    status: str
    protocol: str


@dataclass
class Port:
    name: str
    status: str
    vlan: str
    duplex: str
    speed: str
    description: str = ""
    mac_count: int = 0


@dataclass
class PortError:
    align: int = 0
    fcs: int = 0
    tx: int = 0
    rx: int = 0
    undersize: int = 0
    discard: int = 0

    @property
    def total(self):
        return (
            self.align
            + self.fcs
            + self.tx
            + self.rx
            + self.undersize
            + self.discard
        )


@dataclass
class InterfaceDescription:
    interface: str
    status: str
    protocol: str
    description: str


@dataclass
class Switchport:
    name: str
    configuration: Dict[str, str] = field(default_factory=dict)


@dataclass
class MacAddress:
    address: str
    port: str


@dataclass
class ArpEntry:
    ip: str
    mac: str
    interface: str
    age: str


@dataclass
class Device:
    # --------------------------------------------------------
    # PRIMARY IDENTITY
    # --------------------------------------------------------

    # Primary observed identity.
    #
    # This should represent the device itself rather than
    # the physical switch port where it was observed.
    device_id: str = "UNKNOWN"

    # Primary MAC associated with the device.
    mac: str = "Unknown"

    # Primary IP associated with the device.
    ip: str = "Unknown"

    # --------------------------------------------------------
    # PHYSICAL LOCATION
    # --------------------------------------------------------

    # The switch port is a location, not the device identity.
    port: str = "Unknown"

    vlan: str = "Unknown"

    # --------------------------------------------------------
    # EXPECTED / DESCRIPTIVE IDENTITY
    # --------------------------------------------------------

    description: str = ""
    device_type: str = "UNKNOWN"
    confidence: str = "LOW"
    vendor: str = "Unknown"

    # --------------------------------------------------------
    # OBSERVED INTERFACES
    # --------------------------------------------------------

    # A single logical device may expose multiple MAC
    # addresses through the same physical switch port.
    mac_addresses: List[str] = field(
        default_factory=list
    )

    ip_addresses: List[str] = field(
        default_factory=list
    )

    # --------------------------------------------------------
    # IDENTITY HISTORY
    # --------------------------------------------------------

    # Previous switch locations where this device was seen.
    previous_ports: List[str] = field(
        default_factory=list
    )

    # Previous primary MAC addresses associated with the device.
    previous_macs: List[str] = field(
        default_factory=list
    )


@dataclass
class Vlan:
    vlan_id: str
    name: str
    status: str
    ports: List[str] = field(default_factory=list)


@dataclass
class SpanningTree:
    root_priority: str = "Unknown"
    root_mac: str = "Unknown"
    bridge_priority: str = "Unknown"
    bridge_mac: str = "Unknown"
    role: str = "UNKNOWN"


@dataclass
class NetworkHealth:
    interfaces_tracked: int = 0
    connected_interfaces: int = 0
    connected_switch_ports: int = 0
    learned_mac_addresses: int = 0
    arp_entries: int = 0
    devices_discovered: int = 0
    vlans_discovered: int = 0
    cdp_neighbors: int = 0
    port_errors: int = 0
    overall: str = "UNKNOWN"


@dataclass
class Switch:
    hostname: str = "Unknown"
    model: str = "Unknown"
    ios: str = "Unknown"
    serial: str = "Unknown"
    uptime: str = "Unknown"

    interfaces: List[Interface] = field(default_factory=list)
    ports: List[Port] = field(default_factory=list)
    port_health: Dict[str, PortError] = field(default_factory=dict)
    descriptions: List[InterfaceDescription] = field(default_factory=list)
    switchports: Dict[str, Switchport] = field(default_factory=dict)
    mac_addresses: List[MacAddress] = field(default_factory=list)
    arp_entries: List[ArpEntry] = field(default_factory=list)
    devices: List[Device] = field(default_factory=list)
    vlans: List[Vlan] = field(default_factory=list)

    default_gateway: str = "Unknown"
    cdp_neighbors: List[str] = field(default_factory=list)

    spanning_tree: SpanningTree = field(
        default_factory=SpanningTree
    )

    health: NetworkHealth = field(
        default_factory=NetworkHealth
    )

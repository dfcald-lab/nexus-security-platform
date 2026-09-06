#!/usr/bin/env python3

import socket
import fcntl
import struct

def get_hostname():
    return socket.gethostname()

def get_ipv4_address(interface):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        address = fcntl.ioctl(
            sock.fileno(),
            0x8915,
            struct.pack("256s", interface.encode("utf-8")[:15])
        )

        return socket.inet_ntoa(address[20:24])

    except OSError:
        return "N/A"

    finally:
        sock.close()

def get_interfaces():
    interfaces = []

    for _, name in socket.if_nameindex():
        interface_path = f"/sys/class/net/{name}"

        try:
            with open(f"{interface_path}/address", "r") as file:
                mac = file.read().strip()

            with open(f"{interface_path}/operstate", "r") as file:
                state = file.read().strip()

            with open(f"{interface_path}/mtu", "r") as file:
                mtu = file.read().strip()

            interfaces.append({
                "name": name,
                "mac": mac,
                "state": state,
                "mtu": mtu,
                "ipv4": get_ipv4_address(name)
            })

        except (FileNotFoundError, PermissionError, OSError):
            continue

    return interfaces


hostname = get_hostname()
interfaces = get_interfaces()

print(f"Hostname: {hostname}")
print("Network Interfaces:")

for interface in interfaces:
    print(
        f"  Interface: {interface['name']} | "
        f"State: {interface['state']} | "
        f"MAC: {interface['mac']} | "
	f"IPv4: {interface['ipv4']} | "
        f"MTU: {interface['mtu']}"
    )

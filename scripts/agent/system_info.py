#!/usr/bin/env python3

import shutil
import socket
import fcntl
import struct
import time


def get_os_info():
    os_info = {}

    with open("/etc/os-release", "r") as file:
        for line in file:
            line = line.strip()

            if "=" in line:
                key, value = line.split("=", 1)
                os_info[key] = value.strip('"')

    return os_info


def get_kernel_info():
    with open("/proc/sys/kernel/ostype", "r") as file:
        ostype = file.read().strip()

    with open("/proc/sys/kernel/osrelease", "r") as file:
        osrelease = file.read().strip()

    return ostype, osrelease


def get_uptime():
    with open("/proc/uptime", "r") as file:
        uptime_seconds = float(file.read().split()[0])

    return uptime_seconds


def get_cpu_info():
    cpu_info = {}

    with open("/proc/cpuinfo", "r") as file:
        for line in file:
            if ":" not in line:
                continue

            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()

            if key in ["model name", "cpu cores", "siblings", "cpu MHz"]:
                cpu_info[key] = value

            if len(cpu_info) == 4:
                break

    return cpu_info


def get_memory_info():
    memory = {}

    with open("/proc/meminfo", "r") as file:
        for line in file:
            if line.startswith("MemTotal:"):
                memory["total"] = int(line.split()[1])

            elif line.startswith("MemAvailable:"):
                memory["available"] = int(line.split()[1])

    total = memory["total"]
    available = memory["available"]
    used = total - available
    usage_percent = (used / total) * 100

    return total, available, used, usage_percent


def get_disk_info():
    total, used, free = shutil.disk_usage("/")

    usage_percent = (used / total) * 100

    return total, used, free, usage_percent


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


def get_interface_info():
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

            try:
                with open(f"{interface_path}/speed", "r") as file:
                    speed = file.read().strip()
            except (FileNotFoundError, OSError):
                speed = "N/A"

            statistics_path = f"{interface_path}/statistics"

            with open(f"{statistics_path}/rx_bytes", "r") as file:
                rx_bytes = int(file.read().strip())

            with open(f"{statistics_path}/tx_bytes", "r") as file:
                tx_bytes = int(file.read().strip())

            with open(f"{statistics_path}/rx_packets", "r") as file:
                rx_packets = int(file.read().strip())

            with open(f"{statistics_path}/tx_packets", "r") as file:
                tx_packets = int(file.read().strip())

            with open(f"{statistics_path}/rx_errors", "r") as file:
                rx_errors = int(file.read().strip())

            with open(f"{statistics_path}/tx_errors", "r") as file:
                tx_errors = int(file.read().strip())

            with open(f"{statistics_path}/rx_dropped", "r") as file:
                rx_dropped = int(file.read().strip())

            with open(f"{statistics_path}/tx_dropped", "r") as file:
                tx_dropped = int(file.read().strip())

            interfaces.append({
                "name": name,
                "mac": mac,
                "state": state,
                "mtu": mtu,
                "speed": speed,
                "ipv4": get_ipv4_address(name),
                "rx_bytes": rx_bytes,
                "tx_bytes": tx_bytes,
                "rx_packets": rx_packets,
                "tx_packets": tx_packets,
                "rx_errors": rx_errors,
                "tx_errors": tx_errors,
                "rx_dropped": rx_dropped,
                "tx_dropped": tx_dropped
            })

        except (FileNotFoundError, PermissionError, OSError):
            continue

    return interfaces


def get_interface_rates():
    before = get_interface_info()
    start_time = time.monotonic()

    time.sleep(1)

    after = get_interface_info()
    elapsed = time.monotonic() - start_time

    rates = {}

    for interface in after:
        name = interface["name"]

        previous = next(
            item for item in before
            if item["name"] == name
        )

        rates[name] = {
            "rx_bytes_per_second":
                (interface["rx_bytes"] - previous["rx_bytes"]) / elapsed,

            "tx_bytes_per_second":
                (interface["tx_bytes"] - previous["tx_bytes"]) / elapsed,

            "rx_packets_per_second":
                (interface["rx_packets"] - previous["rx_packets"]) / elapsed,

            "tx_packets_per_second":
                (interface["tx_packets"] - previous["tx_packets"]) / elapsed
        }

    return rates


os_info = get_os_info()
ostype, osrelease = get_kernel_info()
uptime = get_uptime()
cpu_info = get_cpu_info()
total, available, used, usage_percent = get_memory_info()
disk_total, disk_used, disk_free, disk_usage = get_disk_info()
hostname = socket.gethostname()
interfaces = get_interface_info()
rates = get_interface_rates()


print(f"OS: {os_info.get('NAME')}")
print(f"Version: {os_info.get('VERSION_ID')}")
print(f"Codename: {os_info.get('VERSION_CODENAME')}")
print(f"Kernel: {ostype} {osrelease}")
print(f"Uptime: {uptime:.2f} seconds")
print(f"CPU: {cpu_info.get('model name')}")
print(f"CPU Cores: {cpu_info.get('cpu cores')}")
print(f"Logical CPUs: {cpu_info.get('siblings')}")
print(f"CPU MHz: {cpu_info.get('cpu MHz')}")
print(f"Memory Total: {total / 1024 / 1024:.2f} GB")
print(f"Memory Used: {used / 1024 / 1024:.2f} GB")
print(f"Memory Usage: {usage_percent:.2f}%")
print(f"Disk Total: {disk_total / (1024**3):.2f} GB")
print(f"Disk Used: {disk_used / (1024**3):.2f} GB")
print(f"Disk Usage: {disk_usage:.2f}%")
print(f"Hostname: {hostname}")

print("Network Interfaces:")

for interface in interfaces:
    rate = rates[interface["name"]]

    print(
        f"  Interface: {interface['name']} | "
        f"State: {interface['state']} | "
        f"MAC: {interface['mac']} | "
        f"IPv4: {interface['ipv4']} | "
        f"MTU: {interface['mtu']} | "
        f"Speed: {interface['speed']} Mbps"
    )

    print(
        f"    RX: {interface['rx_bytes']} bytes | "
        f"TX: {interface['tx_bytes']} bytes | "
        f"RX Packets: {interface['rx_packets']} | "
        f"TX Packets: {interface['tx_packets']}"
    )

    print(
        f"    RX Errors: {interface['rx_errors']} | "
        f"TX Errors: {interface['tx_errors']} | "
        f"RX Dropped: {interface['rx_dropped']} | "
        f"TX Dropped: {interface['tx_dropped']}"
    )

    print(
        f"    RX Rate: {rate['rx_bytes_per_second']:.2f} B/s | "
        f"TX Rate: {rate['tx_bytes_per_second']:.2f} B/s | "
        f"RX Packets/s: {rate['rx_packets_per_second']:.2f} | "
        f"TX Packets/s: {rate['tx_packets_per_second']:.2f}"
    )

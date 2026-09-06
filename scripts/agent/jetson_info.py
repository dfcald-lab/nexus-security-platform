#!/usr/bin/env python3

import argparse
import json
import subprocess


JETSON_HOST = "192.0.2.26"
JETSON_USER = "jetson"
SSH_KEY = "~/.ssh/nexus_jetson"


def run_ssh(command):
    result = subprocess.run(
        [
            "ssh",
            "-i",
            SSH_KEY,
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            f"{JETSON_USER}@{JETSON_HOST}",
            command,
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
            or "SSH command failed"
        )

    return result.stdout.strip()


def collect_identity():
    hostname = run_ssh(
        "hostname"
    )

    mac = run_ssh(
        "cat /sys/class/net/enP8p1s0/address"
    )

    ipv4 = run_ssh(
        "ip -4 -o addr show enP8p1s0 "
        "| awk '{print $4}'"
    )

    os_name = run_ssh(
        ". /etc/os-release; "
        "printf '%s' \"$PRETTY_NAME\""
    )

    return {
        "hostname": hostname,
        "interface": "enP8p1s0",
        "mac": mac,
        "ipv4": ipv4,
        "os": os_name,
        "source": {
            "transport": "ssh",
            "host": JETSON_HOST,
            "evidence": "jetson_endpoint",
        },
    }


def print_report(data):
    print()
    print(
        "============ NEXUS JETSON INTELLIGENCE ============"
    )
    print()

    print(
        f"Hostname:     {data['hostname']}"
    )
    print(
        f"Interface:    {data['interface']}"
    )
    print(
        f"MAC:          {data['mac']}"
    )
    print(
        f"IPv4:         {data['ipv4']}"
    )
    print(
        f"OS:           {data['os']}"
    )

    print()
    print(
        "SSH endpoint verified: YES"
    )
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Nexus Jetson endpoint collector"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON",
    )

    args = parser.parse_args()

    try:
        identity = collect_identity()

    except RuntimeError as error:
        raise SystemExit(
            f"ERROR: {error}"
        )

    if args.json:
        print(
            json.dumps(
                identity,
                indent=2,
            )
        )
        return

    print_report(identity)


if __name__ == "__main__":
    main()

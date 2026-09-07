#!/usr/bin/env python3

import argparse
import copy
import json
import secrets
import shutil
import subprocess
from pathlib import Path


NEXUS = Path.home() / "nexus"

SOURCE_SNAPSHOT = (
    NEXUS
    / "monitoring"
    / "snapshots"
    / "current.json"
)

TEST_DIR = Path("/tmp/nexus-simulation")


def load_snapshot():
    with SOURCE_SNAPSHOT.open(
        encoding="utf-8"
    ) as file:
        return json.load(file)


def save_snapshot(path, data):
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            data,
            file,
            indent=2,
        )


def save_device_history(
    device,
):
    """
    Write an isolated device-history record using
    the same schema as production NEXUS device history.
    """

    history_dir = (
        TEST_DIR
        / "devices"
    )

    history_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    device_id = device["device_id"]

    record = {
        "device_id": device_id,
        "first_seen": (
            "2026-01-01T00:00:00+00:00"
        ),
        "last_seen": (
            "2026-01-01T00:00:00+00:00"
        ),
        "observations": 1,
        "current": {
            "port": device.get(
                "port",
                "Unknown",
            ),
            "vlan": device.get(
                "vlan",
                "Unknown",
            ),
            "ip": device.get(
                "ip",
                "Unknown",
            ),
            "ip_addresses": device.get(
                "ip_addresses",
                [],
            ),
            "mac_addresses": device.get(
                "mac_addresses",
                [device_id],
            ),
            "device_type": device.get(
                "device_type",
                "SIMULATED",
            ),
            "vendor": device.get(
                "vendor",
                "NEXUS",
            ),
            "description": device.get(
                "description",
                "NEXUS-SIMULATED",
            ),
            "mac": device.get(
                "mac",
                device_id,
            ),
        },
        "history": {
            "previous_ports": [],
            "previous_macs": [],
            "previous_ips": [],
        },
    }

    output = {
        "devices": {
            device_id: record
        }
    }

    output_path = (
        history_dir
        / "device_history.json"
    )

    save_snapshot(
        output_path,
        output,
    )

    return output_path


def all_known_macs(snapshot):
    known = set()

    for device in snapshot.get(
        "devices",
        {},
    ).values():

        device_mac = device.get("mac")

        if device_mac:
            known.add(
                str(device_mac).lower()
            )

        for mac in device.get(
            "mac_addresses",
            [],
        ):
            known.add(
                str(mac).lower()
            )

    return known


def generate_mac(known):
    while True:
        raw = bytearray(
            secrets.token_bytes(6)
        )

        # Locally administered + unicast.
        raw[0] = (
            raw[0] & 0xFC
        ) | 0x02

        mac = (
            f"{raw[0]:02x}{raw[1]:02x}."
            f"{raw[2]:02x}{raw[3]:02x}."
            f"{raw[4]:02x}{raw[5]:02x}"
        )

        if mac.lower() not in known:
            known.add(
                mac.lower()
            )

            return mac


def choose_free_ports(
    snapshot,
    count=2,
):
    candidates = []

    for port, data in snapshot.get(
        "ports",
        {},
    ).items():

        status = str(
            data.get(
                "status",
                "",
            )
        ).lower()

        mac_count = data.get(
            "mac_count",
            0,
        )

        if (
            status == "notconnect"
            and mac_count == 0
        ):
            candidates.append(
                port
            )

    if len(candidates) < count:
        raise RuntimeError(
            f"Need {count} unused ports, "
            f"but only found {len(candidates)}."
        )

    return candidates[:count]


def make_simulated_device(
    snapshot
):
    known = all_known_macs(
        snapshot
    )

    device_id = generate_mac(
        known
    )

    extra_mac = generate_mac(
        known
    )

    old_port, new_port = (
        choose_free_ports(
            snapshot,
            count=2,
        )
    )

    vlan = str(
        snapshot.get(
            "ports",
            {},
        )
        .get(
            old_port,
            {},
        )
        .get(
            "vlan",
            "1",
        )
    )

    device = {
        "device_id": device_id,
        "mac": device_id,
        "port": old_port,
        "ip": "Unknown",
        "ip_addresses": [],
        "vlan": vlan,
        "description": "NEXUS-SIMULATED",
        "device_type": "SIMULATED",
        "confidence": "HIGH",
        "vendor": "NEXUS",
        "mac_addresses": [
            device_id
        ],
        "observed_description": (
            "NEXUS-SIMULATED"
        ),
        "observed_device_type": (
            "SIMULATED"
        ),
        "identity_description": (
            "NEXUS-SIMULATED"
        ),
    }

    return (
        device,
        device_id,
        extra_mac,
        old_port,
        new_port,
    )


def configure_port(
    data,
    port,
    *,
    name,
    vlan,
    status,
    mac_count,
):
    ports = data.setdefault(
        "ports",
        {},
    )

    port_data = ports.setdefault(
        port,
        {},
    )

    port_data["name"] = name
    port_data["status"] = status
    port_data["vlan"] = vlan
    port_data.setdefault(
        "duplex",
        "auto",
    )
    port_data.setdefault(
        "speed",
        "auto",
    )
    port_data["mac_count"] = mac_count


def prepare_snapshots(
    source,
    event,
):
    old_data = copy.deepcopy(
        source
    )

    new_data = copy.deepcopy(
        source
    )

    (
        device,
        device_id,
        extra_mac,
        old_port,
        new_port,
    ) = make_simulated_device(
        source
    )

    old_device = copy.deepcopy(
        device
    )

    new_device = copy.deepcopy(
        device
    )

    old_data.setdefault(
        "devices",
        {}
    )[device_id] = old_device

    new_data.setdefault(
        "devices",
        {}
    )[device_id] = new_device

    configure_port(
        old_data,
        old_port,
        name="NEXUS-SIMULATED",
        vlan=device["vlan"],
        status="connected",
        mac_count=1,
    )

    configure_port(
        new_data,
        old_port,
        name="NEXUS-SIMULATED",
        vlan=device["vlan"],
        status="connected",
        mac_count=1,
    )

    if event == "mac_added":

        new_device["mac_addresses"].append(
            extra_mac
        )

        configure_port(
            new_data,
            old_port,
            name="NEXUS-SIMULATED",
            vlan=device["vlan"],
            status="connected",
            mac_count=2,
        )

    elif event == "mac_removed":

        old_device["mac_addresses"].append(
            extra_mac
        )

        new_device["mac_addresses"] = [
            device_id
        ]

        configure_port(
            old_data,
            old_port,
            name="NEXUS-SIMULATED",
            vlan=device["vlan"],
            status="connected",
            mac_count=2,
        )

    elif event == "device_moved":

        new_device["port"] = new_port

        configure_port(
            new_data,
            old_port,
            name="",
            vlan=device["vlan"],
            status="notconnect",
            mac_count=0,
        )

        configure_port(
            new_data,
            new_port,
            name="NEXUS-SIMULATED",
            vlan=device["vlan"],
            status="connected",
            mac_count=1,
        )

    else:
        raise ValueError(
            f"Unsupported simulation event: {event}"
        )

    return (
        old_data,
        new_data,
        {
            "device_id": device_id,
            "extra_mac": extra_mac,
            "old_port": old_port,
            "new_port": new_port,
        },
    )


SIMULATION_ROOT = Path(
    "/tmp/nexus-simulation"
)

SIMULATION_EVENTS = (
    SIMULATION_ROOT
    / "events"
)

SIMULATION_DEVICES = (
    SIMULATION_ROOT
    / "devices"
)

SIMULATION_TOPOLOGY = (
    SIMULATION_ROOT
    / "topology"
)

SIMULATION_INTELLIGENCE = (
    SIMULATION_ROOT
    / "intelligence"
)

SIMULATION_STATE = (
    SIMULATION_ROOT
    / "jetson_state.json"
)

SIMULATION_EVENT_LOG = (
    SIMULATION_EVENTS
    / "events.jsonl"
)

SIMULATION_EVENT_STATE = (
    SIMULATION_EVENTS
    / "event_state.json"
)

SIMULATION_ALERT_STATE = (
    SIMULATION_EVENTS
    / "alert_state.json"
)

SIMULATION_INCIDENT_HISTORY = (
    SIMULATION_EVENTS
    / "incident_history.json"
)

SIMULATION_DEVICE_HISTORY = (
    SIMULATION_DEVICES
    / "device_history.json"
)

SIMULATION_TOPOLOGY_FILE = (
    SIMULATION_TOPOLOGY
    / "current.json"
)


def prepare_simulation_environment():
    """
    Create an isolated NEXUS simulation workspace.
    """

    if SIMULATION_ROOT.exists():
        shutil.rmtree(
            SIMULATION_ROOT
        )

    for directory in (
        SIMULATION_EVENTS,
        SIMULATION_DEVICES,
        SIMULATION_TOPOLOGY,
        SIMULATION_INTELLIGENCE,
    ):
        directory.mkdir(
            parents=True,
            exist_ok=True,
        )

    production_topology = (
        NEXUS
        / "monitoring"
        / "topology"
        / "current.json"
    )

    if production_topology.exists():
        shutil.copy2(
            production_topology,
            SIMULATION_TOPOLOGY_FILE,
        )


def run_isolated_command(
    args,
    *,
    env=None,
):
    """
    Run one NEXUS pipeline stage inside
    the isolated simulation environment.
    """

    result = subprocess.run(
        args,
        cwd=NEXUS,
        env=env,
        check=False,
    )

    if result.returncode != 0:
        raise SystemExit(
            f"ERROR: simulation stage failed "
            f"with exit code {result.returncode}: "
            f"{args}"
        )

    return result.returncode


def run_isolated_pipeline(
    old_path,
    new_path,
):
    """
    Execute the deterministic NEXUS pipeline
    using only isolated simulation state.
    """

    base_env = dict(
        __import__("os").environ
    )

    base_env.update(
        {
            "NEXUS_EVENT_DIR": str(
                SIMULATION_EVENTS
            ),
            "NEXUS_EVENT_STATE": str(
                SIMULATION_EVENT_STATE
            ),
            "NEXUS_EVENT_LOG": str(
                SIMULATION_EVENT_LOG
            ),
            "NEXUS_INCIDENT_HISTORY": str(
                SIMULATION_INCIDENT_HISTORY
            ),
            "NEXUS_DEVICE_HISTORY": str(
                SIMULATION_DEVICE_HISTORY
            ),
            "NEXUS_TOPOLOGY": str(
                SIMULATION_TOPOLOGY_FILE
            ),
            "NEXUS_STATE_OUTPUT": str(
                SIMULATION_STATE
            ),
            "NEXUS_INTELLIGENCE_DIR": str(
                SIMULATION_INTELLIGENCE
            ),
            "NEXUS_JETSON_STATE": str(
                SIMULATION_STATE
            ),
        }
    )

    hardware_state = (
        SIMULATION_ROOT
        / "hardware"
        / "state.json"
    )

    hardware_state.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    production_hardware_state = (
        NEXUS
        / "hardware"
        / "state.json"
    )

    if production_hardware_state.exists():
        shutil.copy2(
            production_hardware_state,
            hardware_state,
        )

    print()
    print("=" * 60)
    print("      ISOLATED NEXUS PIPELINE")
    print("=" * 60)

    print()
    print("[1/6] Change detection")

    env = dict(base_env)

    run_isolated_command(
        [
            "python3",
            "-m",
            "scripts.agent.switch_diff",
            str(old_path),
            str(new_path),
            "--live",
        ],
        env=env,
    )

    print()
    print("[2/6] Event state")

    run_isolated_command(
        [
            "python3",
            "-m",
            "scripts.agent.event_state",
            "--monitor-run",
        ],
        env=env,
    )

    print()
    print("[3/6] Event alerts")

    run_isolated_command(
        [
            "python3",
            "-m",
            "scripts.agent.event_alert",
        ],
        env=env,
    )

    print()
    print("[4/6] Jetson state")

    run_isolated_command(
        [
            "python3",
            "-m",
            "scripts.agent.publish_jetson_state",
        ],
        env=env,
    )

    print()
    print("[5/6] Intelligence")

    run_isolated_command(
        [
            "python3",
            "-m",
            "scripts.agent.nexus_intelligence",
        ],
        env=env,
    )

    print()
    print("[6/6] AI")

    run_isolated_command(
        [
            "python3",
            "-m",
            "scripts.agent.nexus_ai",
        ],
        env=env,
    )

    print()
    print("=" * 60)
    print("      ISOLATED PIPELINE COMPLETE")
    print("=" * 60)

    return {
        "events": SIMULATION_EVENT_LOG,
        "event_state": SIMULATION_EVENT_STATE,
        "alerts": SIMULATION_ALERT_STATE,
        "jetson_state": SIMULATION_STATE,
        "intelligence": (
            SIMULATION_INTELLIGENCE
            / "current.json"
        ),
        "ai_result": (
            SIMULATION_INTELLIGENCE
            / "ai_result.json"
        ),
    }


def run_switch_diff(
    old_path,
    new_path,
    scenario,
):
    print()
    print("=" * 60)
    print("       NEXUS SIMULATION")
    print("=" * 60)
    print()

    print(
        f"Scenario:           {scenario}"
    )

    print()
    print(
        f"OLD snapshot:       {old_path}"
    )
    print(
        f"NEW snapshot:       {new_path}"
    )

    result = subprocess.run(
        [
            "python3",
            "-m",
            "scripts.agent.switch_diff",
            str(old_path),
            str(new_path),
        ],
        cwd=NEXUS,
        check=False,
    )

    return result.returncode


def main():

    parser = argparse.ArgumentParser(
        description=(
            "Safely simulate NEXUS "
            "network events."
        )
    )

    parser.add_argument(
        "--event",
        required=True,
        choices=[
            "mac_added",
            "mac_removed",
            "device_moved",
        ],
        help="Simulation scenario.",
    )

    parser.add_argument(
        "--keep",
        action="store_true",
        help=(
            "Keep temporary simulation "
            "snapshots."
        ),
    )

    args = parser.parse_args()

    if not SOURCE_SNAPSHOT.exists():
        raise SystemExit(
            "ERROR: Source snapshot not found: "
            f"{SOURCE_SNAPSHOT}"
        )

    prepare_simulation_environment()

    old_path = (
        TEST_DIR
        / "old.json"
    )

    new_path = (
        TEST_DIR
        / "new.json"
    )

    source = load_snapshot()

    (
        old_data,
        new_data,
        details,
    ) = prepare_snapshots(
        source,
        args.event,
    )

    save_snapshot(
        old_path,
        old_data,
    )

    save_snapshot(
        new_path,
        new_data,
    )

    device_history_path = (
        save_device_history(
            new_data["devices"][
                details["device_id"]
            ]
        )
    )

    print(
        "Generated synthetic identity:"
    )

    print(
        f"  Device ID:     "
        f"{details['device_id']}"
    )

    print(
        f"  Extra MAC:     "
        f"{details['extra_mac']}"
    )

    print(
        f"  Original port: "
        f"{details['old_port']}"
    )

    print(
        f"  Move target:   "
        f"{details['new_port']}"
    )

    print(
        f"  Device history: "
        f"{device_history_path}"
    )

    result = run_switch_diff(
        old_path,
        new_path,
        args.event,
    )

    pipeline_paths = run_isolated_pipeline(
        old_path,
        new_path,
    )

    print()

    print("Simulation outputs:")

    for name, output_path in pipeline_paths.items():

        print(
            f"  {name:<14} {output_path}"
        )

    print()
    print("=" * 60)
    print(
        "Simulation complete."
    )
    print(
        "Production state was NOT modified."
    )
    print("=" * 60)

    if not args.keep:
        shutil.rmtree(
            TEST_DIR,
            ignore_errors=True,
        )

    raise SystemExit(result)


if __name__ == "__main__":
    main()

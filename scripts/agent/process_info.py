#!/usr/bin/env python3

import os
import pwd
import time

def get_process_cpu_time(pid):
    try:
        with open(f"/proc/{pid}/stat", "r") as file:
            stat = file.read().split()

        utime = int(stat[13])
        stime = int(stat[14])

        return utime + stime

    except (FileNotFoundError, PermissionError, OSError, ValueError):
        return None


def get_process_age(pid):
    try:
        with open(f"/proc/{pid}/stat", "r") as file:
            stat = file.read().split()

        start_ticks = int(stat[21])
        clock_ticks = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
        system_uptime = time.monotonic()

        process_start = start_ticks / clock_ticks
        age = system_uptime - process_start

        return max(0, age)

    except (FileNotFoundError, PermissionError, OSError, ValueError):
        return None


def get_process_cpu_percent(before, after, elapsed):
    if before is None or after is None:
        return None

    clock_ticks = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
    cpu_seconds = (after - before) / clock_ticks

    return (cpu_seconds / elapsed) * 100


def get_total_memory_kb():
    try:
        with open("/proc/meminfo", "r") as file:
            for line in file:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1])
    except (FileNotFoundError, PermissionError, OSError, ValueError):
        return None

    return None


def get_processes():
    processes = []

    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue

        process_path = f"/proc/{pid}"

        try:
            with open(f"{process_path}/comm", "r") as file:
                name = file.read().strip()

            with open(f"{process_path}/cmdline", "rb") as file:
                command_line = file.read().replace(b"\x00", b" ").decode(
                    "utf-8", errors="replace"
                ).strip()

            with open(f"{process_path}/status", "r") as file:
                status = {}

                for line in file:
                    if ":" not in line:
                        continue

                    key, value = line.split(":", 1)
                    status[key] = value.strip()

            uid = status.get("Uid", "").split()[0]

            try:
                username = pwd.getpwuid(int(uid)).pw_name
            except (KeyError, ValueError):
                username = "unknown"

            cpu_time = get_process_cpu_time(pid)
            age_seconds = get_process_age(pid)

            processes.append({
                "pid": pid,
                "name": name,
                "cpu_time": cpu_time,
                "age_seconds": age_seconds,
                "cpu_percent": None,
                "state": status.get("State"),
                "ppid": status.get("PPid"),
                "uid": uid,
                "username": username,
                "command_line": command_line,
                "memory": status.get("VmRSS"),
                "virtual_memory": status.get("VmSize"),
                "threads": status.get("Threads")
            })

        except (FileNotFoundError, PermissionError):
            continue

    return processes


def calculate_cpu_usage(before, after, elapsed):
    cpu_usage = {}

    ticks_per_second = os.sysconf(
        os.sysconf_names["SC_CLK_TCK"]
    )

    previous = {
        process["pid"]: process
        for process in before
    }

    for process in after:
        pid = process["pid"]
        old = previous.get(pid)

        if old is None:
            cpu_usage[pid] = None
            continue

        if old["cpu_time"] is None or process["cpu_time"] is None:
            cpu_usage[pid] = None
            continue

        cpu_ticks = process["cpu_time"] - old["cpu_time"]
        cpu_seconds = cpu_ticks / ticks_per_second

        cpu_usage[pid] = (cpu_seconds / elapsed) * 100

    return cpu_usage

before = get_processes()
start = time.monotonic()
time.sleep(0.5)
after = get_processes()
elapsed = time.monotonic() - start

cpu_usage = calculate_cpu_usage(before, after, elapsed)

total_memory_kb = get_total_memory_kb()

for process in after:
    process["cpu_percent"] = cpu_usage.get(process["pid"])

    age = process["age_seconds"]
    if age is not None:
        days, remainder = divmod(int(age), 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)

        if days:
            process["age"] = f"{days}d {hours}h {minutes}m"
        elif hours:
            process["age"] = f"{hours}h {minutes}m"
        elif minutes:
            process["age"] = f"{minutes}m {seconds}s"
        else:
            process["age"] = f"{seconds}s"
    else:
        process["age"] = "unknown"

    if process["memory"] and total_memory_kb:
        memory_kb = int(process["memory"].split()[0])
        process["memory_percent"] = (memory_kb / total_memory_kb) * 100
    else:
        process["memory_percent"] = None

after.sort(
    key=lambda process: int(
        process["memory"].split()[0]
    ) if process["memory"] else 0,
    reverse=True
)

def print_processes(processes):
    for process in processes:
        print(
            f"PID: {process['pid']} | "
            f"Name: {process['name']} | "
            f"State: {process['state']} | "
            f"PPID: {process['ppid']} | "
            f"UID: {process['uid']} | "
            f"User: {process['username']} | "
            f"Age: {process['age']} | "
            f"RAM: {process['memory']} | "
            f"MEM: {process['memory_percent'] if process['memory_percent'] is not None else 0.0:.2f}% | "
            f"Virtual: {process['virtual_memory']} | "
            f"Threads: {process['threads']} | "
            f"CPU: {process['cpu_percent'] if process['cpu_percent'] is not None else 0.0:.2f}% | "
            f"Command: {process['command_line']}"
        )


print_processes(after)

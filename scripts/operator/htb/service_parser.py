#!/usr/bin/env python3

import re


PORT_PATTERN = re.compile(
    r"^\s*(\d+)\/(tcp|udp)\s+"
    r"(\S+)"
    r"(?:\s+(.*))?$",
    re.IGNORECASE,
)


def parse_nmap_table(text):
    services = []

    for raw_line in text.splitlines():

        line = raw_line.strip()

        if not line:
            continue

        match = PORT_PATTERN.match(line)

        if not match:
            continue

        port = int(
            match.group(1)
        )

        protocol = match.group(2).lower()

        state = match.group(3).lower()

        remainder = (
            match.group(4) or ""
        ).strip()

        parts = remainder.split(
            None,
            1,
        )

        service = (
            parts[0]
            if parts
            else ""
        )

        version = (
            parts[1]
            if len(parts) > 1
            else ""
        )

        services.append(
            {
                "port": port,
                "protocol": protocol,
                "state": state,
                "service": service,
                "version": version,
                "raw": line,
            }
        )

    return services


def main():
    sample = """
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp   open  http    Apache httpd 2.4.41
8080/tcp open  http    Apache Tomcat 9.0.65
"""

    for service in parse_nmap_table(
        sample
    ):
        print(service)


if __name__ == "__main__":
    main()

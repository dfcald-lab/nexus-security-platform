#!/usr/bin/env python3

import argparse
import json
import shlex
from datetime import datetime, timezone
from pathlib import Path

from scripts.operator.htb.service_parser import (
    parse_nmap_table,
)

from scripts.operator.htb.research import (
    research_service,
)


NEXUS = Path.home() / "nexus"
SESSION_DIR = NEXUS / "operator" / "htb_sessions"


def now():
    return datetime.now(
        timezone.utc
    ).isoformat()


def session_path(name):
    return SESSION_DIR / f"{name}.json"


def load_session(name):
    path = session_path(name)

    if not path.exists():
        return None

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as file:
            session = json.load(file)

        if isinstance(session, dict):
            session.setdefault(
                "services",
                [],
            )
            session.setdefault(
                "research",
                [],
            )
            session.setdefault(
                "evidence",
                [],
            )
            session.setdefault(
                "findings",
                [],
            )
            session.setdefault(
                "notes",
                [],
            )

        return session

    except (
        OSError,
        json.JSONDecodeError,
    ):
        raise RuntimeError(
            f"Could not read HTB session: {path}"
        )


def save_session(session):
    SESSION_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    path = session_path(
        session["name"]
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            session,
            file,
            indent=2,
        )

        file.write("\n")


def create_session(name, target=None):
    existing = load_session(name)

    if existing is not None:
        raise RuntimeError(
            f"HTB session already exists: {name}"
        )

    session = {
        "name": name,
        "created_at": now(),
        "updated_at": now(),
        "target": target or "",
        "services": [],
        "findings": [],
        "notes": [],
        "research": [],
        "evidence": [],
    }

    save_session(session)

    return session


def import_services(
    session,
    nmap_output,
):
    services = parse_nmap_table(
        nmap_output
    )

    existing = session.get(
        "services",
        [],
    )

    if not isinstance(
        existing,
        list,
    ):
        existing = []

    merged = {}

    for service in existing:
        if not isinstance(
            service,
            dict,
        ):
            continue

        key = (
            service.get("port"),
            service.get("protocol"),
        )

        merged[key] = service

    for service in services:
        key = (
            service.get("port"),
            service.get("protocol"),
        )

        merged[key] = service

    session["services"] = sorted(
        merged.values(),
        key=lambda item: (
            int(
                item.get(
                    "port",
                    0,
                )
            ),
            str(
                item.get(
                    "protocol",
                    "",
                )
            ),
        ),
    )

    session["updated_at"] = now()

    save_session(
        session
    )

    return services



def research_services(
    session,
):
    """
    Research every stored HTB service.

    Research uses:
      - NVD affected-version data
      - CVE condition extraction
      - Exploit-DB metadata

    No exploit code is downloaded or executed.
    """

    session.setdefault(
        "research",
        [],
    )

    records = []

    for service in session.get(
        "services",
        [],
    ):

        try:
            record = research_service(
                service,
                session.get(
                    "evidence",
                    [],
                ),
            )

        except Exception as error:

            record = {
                "timestamp": now(),
                "port": service.get(
                    "port"
                ),
                "protocol": service.get(
                    "protocol"
                ),
                "service": service.get(
                    "service"
                ),
                "version": service.get(
                    "version"
                ),
                "error": str(
                    error
                ),
                "nvd_results": [],
                "searchsploit": {
                    "available": False,
                    "results": [],
                    "message": "Research failed.",
                },
            }

        records.append(
            record
        )

    session["research"] = records
    session["updated_at"] = now()

    save_session(
        session
    )

    return records

def add_research(
    session,
    record,
):
    session.setdefault(
        "research",
        [],
    )

    if not isinstance(
        session["research"],
        list,
    ):
        session["research"] = []

    session["research"].append(
        record
    )

    session["updated_at"] = now()

    save_session(
        session
    )


def add_finding(
    session,
    category,
    content,
):
    session["findings"].append(
        {
            "timestamp": now(),
            "category": category,
            "content": content,
        }
    )

    session["updated_at"] = now()

    save_session(session)



def add_evidence(
    session,
    condition,
    status,
    source,
    content,
):
    """
    Store explicit operator evidence.

    status:
        VERIFIED
        NOT_VERIFIED
        UNKNOWN
    """

    status = str(
        status or "UNKNOWN"
    ).upper()

    if status not in {
        "VERIFIED",
        "NOT_VERIFIED",
        "UNKNOWN",
    }:
        raise ValueError(
            "Evidence status must be "
            "VERIFIED, NOT_VERIFIED, or UNKNOWN."
        )

    session.setdefault(
        "evidence",
        [],
    )

    session["evidence"].append(
        {
            "timestamp": now(),
            "condition": condition,
            "status": status,
            "source": source,
            "content": content,
        }
    )

    session["updated_at"] = now()

    save_session(
        session
    )


def add_note(
    session,
    content,
):
    session["notes"].append(
        {
            "timestamp": now(),
            "content": content,
        }
    )

    session["updated_at"] = now()

    save_session(session)


def show_session(session):

    print()
    print(
        "============ NEXUS HTB SESSION ============"
    )
    print()

    print(
        "Name:",
        session["name"],
    )

    print(
        "Target:",
        session["target"] or "Not set",
    )

    print(
        "Created:",
        session["created_at"],
    )

    print(
        "Updated:",
        session["updated_at"],
    )

    print()
    print(
        "Services:",
        len(
            session.get(
                "services",
                [],
            )
        ),
    )

    for service in session.get(
        "services",
        [],
    ):

        print(
            f"- {service.get('port')}/"
            f"{service.get('protocol')} "
            f"{service.get('service') or 'UNKNOWN'} "
            f"{service.get('version') or 'VERSION UNKNOWN'}"
        )

    print()
    print(
        "Evidence:",
        len(
            session.get(
                "evidence",
                [],
            )
        ),
    )

    for item in session.get(
        "evidence",
        [],
    ):

        print(
            f"- [{item.get('status', 'UNKNOWN')}] "
            f"{item.get('condition', '')} "
            f"({item.get('source', 'UNKNOWN')}) "
            f"{item.get('content', '')}"
        )

    print()
    print(
        "Research records:",
        len(
            session.get(
                "research",
                [],
            )
        ),
    )

    print()
    print(
        "Findings:",
        len(session["findings"]),
    )

    for finding in session["findings"]:

        print(
            f"- [{finding['category']}] "
            f"{finding['content']}"
        )

    print()
    print(
        "Notes:",
        len(session["notes"]),
    )

    for note in session["notes"]:

        print(
            f"- {note['content']}"
        )

    print()


def interactive(name):

    session = load_session(name)

    if session is None:
        session = create_session(name)

    print()
    print(
        "============ NEXUS HTB ============"
    )
    print()

    print(
        "Session:",
        session["name"],
    )

    print(
        "Commands:"
    )

    print(
        "  target <value>"
    )

    print(
        "  finding <category> <content>"
    )

    print(
        "  services <nmap output>"
    )

    print(
        "  research"
    )

    print(
        "  evidence <status> <condition> <source> <content>"
    )

    print(
        "  note <content>"
    )

    print(
        "  show"
    )

    print(
        "  exit"
    )

    print()

    while True:

        try:
            command = input(
                "htb> "
            ).strip()

        except EOFError:
            break

        if not command:
            continue

        if command.lower() in {
            "exit",
            "quit",
        }:
            break

        if command == "show":

            show_session(
                session
            )

            continue

        if command.startswith(
            "target "
        ):

            session["target"] = (
                command[7:].strip()
            )

            session["updated_at"] = now()

            save_session(
                session
            )

            print(
                "Target saved."
            )

            continue

        if command.startswith(
            "evidence "
        ):

            remainder = (
                command[9:].strip()
            )

            try:
                parts = shlex.split(
                    remainder
                )
            except ValueError as error:
                print(
                    f"Error parsing evidence: {error}"
                )
                continue

            if len(parts) != 4:

                print(
                    "Usage: evidence "
                    "<status> "
                    "\"<condition>\" "
                    "<source> "
                    "\"<content>\""
                )

                continue

            status, condition, source, content = (
                parts
            )

            try:

                add_evidence(
                    session,
                    condition,
                    status,
                    source,
                    content,
                )

                print(
                    "Evidence saved."
                )

            except ValueError as error:

                print(
                    f"Error: {error}"
                )

            continue

        if command == "research":

            if not session.get(
                "services",
                [],
            ):

                print(
                    "No services stored. "
                    "Import services first."
                )

                continue

            records = research_services(
                session
            )

            print(
                f"Researched {len(records)} service(s)."
            )

            total_cves = sum(
                len(
                    record.get(
                        "nvd_results",
                        [],
                    )
                )
                for record in records
            )

            exploit_refs = sum(
                len(
                    cve.get(
                        "exploit_db",
                        {}
                    ).get(
                        "results",
                        [],
                    )
                )
                for record in records
                for cve in record.get(
                    "nvd_results",
                    [],
                )
            )

            print(
                f"Potential CVE matches: {total_cves}"
            )

            print(
                f"Exploit-DB references: {exploit_refs}"
            )

            continue

        if command.startswith(
            "services "
        ):

            nmap_output = (
                command[9:].strip()
            )

            if not nmap_output:

                print(
                    "Usage: services <nmap output>"
                )

                continue

            services = import_services(
                session,
                nmap_output,
            )

            print(
                f"Imported {len(services)} service(s)."
            )

            continue

        if command.startswith(
            "note "
        ):

            add_note(
                session,
                command[5:].strip(),
            )

            print(
                "Note saved."
            )

            continue

        if command.startswith(
            "finding "
        ):

            remainder = (
                command[8:].strip()
            )

            parts = remainder.split(
                " ",
                1,
            )

            if len(parts) != 2:

                print(
                    "Usage: finding <category> <content>"
                )

                continue

            category, content = parts

            add_finding(
                session,
                category,
                content,
            )

            print(
                "Finding saved."
            )

            continue

        print(
            "Unknown command."
        )


def main():

    parser = argparse.ArgumentParser(
        description="NEXUS HTB session manager"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    create_parser = subparsers.add_parser(
        "create"
    )

    create_parser.add_argument(
        "name"
    )

    create_parser.add_argument(
        "--target",
        default="",
    )

    open_parser = subparsers.add_parser(
        "open"
    )

    open_parser.add_argument(
        "name"
    )

    args = parser.parse_args()

    if args.command == "create":

        session = create_session(
            args.name,
            args.target,
        )

        print(
            f"Created HTB session: {session['name']}"
        )

    elif args.command == "open":

        interactive(
            args.name
        )


if __name__ == "__main__":
    main()

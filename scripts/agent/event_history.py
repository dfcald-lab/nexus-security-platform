#!/usr/bin/env python3

import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path


# ============================================================
# NEXUS EVENT HISTORY
# ============================================================

EVENT_FILE = (
    Path.home()
    / "nexus"
    / "monitoring"
    / "events"
    / "events.jsonl"
)


# ============================================================
# ARGUMENTS
# ============================================================

def parse_arguments():

    parser = argparse.ArgumentParser(
        description="Nexus network event history"
    )

    parser.add_argument(
        "--severity",
        choices=[
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO",
        ],
        help="Show only events with this severity",
    )

    parser.add_argument(
        "--last",
        type=int,
        metavar="N",
        help="Show only the last N events",
    )

    parser.add_argument(
        "--score",
        type=int,
        metavar="N",
        help="Show only events with this score",
    )

    return parser.parse_args()


# ============================================================
# LOAD EVENTS
# ============================================================

def load_events():

    if not EVENT_FILE.exists():

        print(
            f"ERROR: Event log not found: {EVENT_FILE}"
        )

        return []

    events = []

    with EVENT_FILE.open("r") as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            try:

                events.append(
                    json.loads(line)
                )

            except json.JSONDecodeError:

                continue

    return events


# ============================================================
# FILTER EVENTS
# ============================================================

def filter_events(
    events,
    severity=None,
    score=None,
    last=None,
):

    filtered = events

    if severity:

        filtered = [
            event
            for event in filtered
            if event.get("severity") == severity
        ]

    if score is not None:

        filtered = [
            event
            for event in filtered
            if event.get("score", 0) == score
        ]

    if last is not None:

        if last <= 0:

            return []

        filtered = filtered[-last:]

    return filtered


# ============================================================
# FORMAT TIMESTAMP
# ============================================================

def format_timestamp(timestamp):

    try:

        value = datetime.fromisoformat(
            timestamp
        )

        return value.astimezone().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    except (
        ValueError,
        TypeError,
    ):

        return timestamp


# ============================================================
# PRINT EVENTS
# ============================================================

def print_events(events):

    for event in events:

        timestamp = format_timestamp(
            event.get(
                "timestamp",
                "Unknown",
            )
        )

        severity = event.get(
            "severity",
            "UNKNOWN",
        )

        score = event.get(
            "score",
            0,
        )

        message = event.get(
            "message",
            "Unknown event",
        )

        print(
            f"{timestamp}  "
            f"{severity:<8} "
            f"+{score:<3} "
            f"{message}"
        )


# ============================================================
# EVENT SUMMARY
# ============================================================

def print_summary(events):

    severity_counts = Counter(
        event.get(
            "severity",
            "UNKNOWN",
        )
        for event in events
    )

    total_score = sum(
        event.get(
            "score",
            0,
        )
        for event in events
    )

    print()

    print(
        "===================================="
    )

    print(
        "             EVENT SUMMARY"
    )

    print(
        "===================================="
    )

    print()

    print(
        f"Total events: {len(events)}"
    )

    print(
        f"Critical:     "
        f"{severity_counts.get('CRITICAL', 0)}"
    )

    print(
        f"High:         "
        f"{severity_counts.get('HIGH', 0)}"
    )

    print(
        f"Medium:       "
        f"{severity_counts.get('MEDIUM', 0)}"
    )

    print(
        f"Low:          "
        f"{severity_counts.get('LOW', 0)}"
    )

    print(
        f"Info:         "
        f"{severity_counts.get('INFO', 0)}"
    )

    print(
        f"Total score:  {total_score}"
    )

    print()


# ============================================================
# MAIN
# ============================================================

def main():

    args = parse_arguments()

    events = load_events()

    events = filter_events(
        events,
        severity=args.severity,
        score=args.score,
        last=args.last,
    )

    print()

    print(
        "===================================="
    )

    print(
        "         NEXUS EVENT HISTORY"
    )

    print(
        "===================================="
    )

    if args.severity:

        print(
            f"Filter: severity={args.severity}"
        )

    if args.score is not None:

        print(
            f"Filter: score={args.score}"
        )

    if args.last is not None:

        print(
            f"Filter: last={args.last}"
        )

    if (
        args.severity
        or args.score is not None
        or args.last is not None
    ):

        print()

    if not events:

        print()

        print(
            "No matching events found."
        )

        print()

        return

    print()

    print_events(events)

    print_summary(events)


if __name__ == "__main__":
    main()

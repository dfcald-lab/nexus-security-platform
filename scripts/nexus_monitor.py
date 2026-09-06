#!/usr/bin/env python3

import os
import subprocess
import sys
import time
from pathlib import Path


NEXUS_DIR = Path.home() / "nexus"
MONITOR_SCRIPT = NEXUS_DIR / "scripts" / "monitor_switch.sh"

INTERVAL_SECONDS = 30


def run_monitor() -> int:
    print("=" * 60, flush=True)
    print("NEXUS MONITOR CYCLE", flush=True)
    print("=" * 60, flush=True)

    result = subprocess.run(
        [str(MONITOR_SCRIPT)],
        cwd=NEXUS_DIR,
        env=os.environ.copy(),
        check=False,
    )

    print(
        f"NEXUS monitor cycle finished with exit code {result.returncode}",
        flush=True,
    )

    return result.returncode


def main() -> None:
    print("NEXUS continuous monitor starting...", flush=True)
    print(f"Repository: {NEXUS_DIR}", flush=True)
    print(f"Monitor:    {MONITOR_SCRIPT}", flush=True)
    print(f"Interval:   {INTERVAL_SECONDS} seconds", flush=True)

    while True:
        try:
            run_monitor()

        except KeyboardInterrupt:
            print("NEXUS monitor stopping.", flush=True)
            sys.exit(0)

        except Exception as exc:
            print(
                f"NEXUS monitor error: {exc}",
                file=sys.stderr,
                flush=True,
            )

        print(
            f"Sleeping {INTERVAL_SECONDS} seconds...",
            flush=True,
        )

        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Explicitly install the pinned parser runtime, online or from a wheel cache."""

import argparse
from pathlib import Path
import platform
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = ROOT / "requirements-runtime.txt"


def build_command(wheel_dir=""):
    command = [
        sys.executable, "-m", "pip", "install",
        "--disable-pip-version-check", "--requirement", str(REQUIREMENTS),
    ]
    if wheel_dir:
        command.extend(["--no-index", "--find-links", str(Path(wheel_dir).expanduser().resolve())])
    return command


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--wheel-dir", default="",
        help="Install only from this controlled offline wheel directory",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if platform.python_implementation() != "CPython" or sys.version_info[:2] != (3, 12):
        parser.error(
            f"unsupported Python {sys.version.split()[0]}; use CPython 3.12.x"
        )
    command = build_command(args.wheel_dir)
    if args.dry_run:
        print(" ".join(command))
        return 0
    completed = subprocess.run(command, cwd=str(ROOT), check=False)
    if completed.returncode:
        return completed.returncode
    from runtime_contract import contract_payload
    payload = contract_payload(require_maven=False)
    failed_packages = [
        item for item in payload["checks"]
        if item["component"].startswith(("python_package:", "python_import:"))
        and item["status"] != "passed"
    ]
    return 1 if failed_packages else 0


if __name__ == "__main__":
    raise SystemExit(main())

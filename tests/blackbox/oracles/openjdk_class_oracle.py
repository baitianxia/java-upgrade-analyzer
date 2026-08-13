"""Independent OpenJDK Oracle for class-level contract transitions."""

from __future__ import annotations

from pathlib import Path
import re
import subprocess


_FLAGS = re.compile(r"^\s*flags:\s*\(0x[0-9a-fA-F]+\)\s*(.*)$")


def _class_flags(javap: str, jar: Path, class_name: str) -> tuple[str, ...]:
    completed = subprocess.run(
        [javap, "-classpath", str(jar), "-v", class_name],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=60,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"javap failed ({completed.returncode}): {completed.stderr[-1000:]}"
        )
    for line in completed.stdout.splitlines():
        matched = _FLAGS.match(line)
        if matched:
            return tuple(sorted(
                value.strip()
                for value in matched.group(1).split(",")
                if value.strip()
            ))
    raise AssertionError(f"class flags not found: {class_name}")


def final_class_transition(
    *, javap: str, base_jar: Path, current_jar: Path, class_name: str,
) -> dict[str, object]:
    """Prove an ACC_FINAL class transition without reading product output."""
    base_flags = _class_flags(javap, base_jar, class_name)
    current_flags = _class_flags(javap, current_jar, class_name)
    if "ACC_FINAL" in base_flags or "ACC_FINAL" not in current_flags:
        raise AssertionError(
            f"expected non-final to final transition: {base_flags} -> {current_flags}"
        )
    owner = class_name.replace(".", "/")
    return {
        "identity": (owner, "<class>", f"L{owner};", "class"),
        "base_flags": base_flags,
        "current_flags": current_flags,
        "added_flags": tuple(sorted(set(current_flags) - set(base_flags))),
        "removed_flags": tuple(sorted(set(base_flags) - set(current_flags))),
    }


__all__ = ["final_class_transition"]

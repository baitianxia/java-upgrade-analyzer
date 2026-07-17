#!/usr/bin/env python3
"""Independent compile-time constant and runtime-link evidence."""

from dataclasses import asdict, dataclass
from pathlib import Path
import re
import subprocess


@dataclass(frozen=True)
class ConstantImpact:
    compile_impact: str
    runtime_link_impact: str
    old_field_has_constant_value: bool
    source_reference_present: bool
    runtime_field_edge_present: bool
    source_artifact_aligned: bool

    def to_dict(self):
        return asdict(self)


def classify_constant_impact(
    *, change_type, old_field_has_constant_value, source_reference_present,
    runtime_field_edge_present, source_artifact_aligned,
):
    if not source_artifact_aligned:
        compile_impact = runtime_impact = "unverified"
    else:
        normalized = str(change_type or "").upper()
        if not source_reference_present:
            compile_impact = "source_reference_absent"
        elif normalized == "CONSTANT_VALUE_CHANGED":
            compile_impact = "recompile_value_change"
        elif normalized in {"REMOVED", "FIELD_REMOVED"}:
            compile_impact = "recompile_break"
        else:
            compile_impact = "recompile_review_required"

        if runtime_field_edge_present:
            runtime_impact = "runtime_link_present"
        elif old_field_has_constant_value and source_reference_present:
            runtime_impact = (
                "inlined_old_value"
                if normalized == "CONSTANT_VALUE_CHANGED"
                else "inlined_no_link"
            )
        else:
            runtime_impact = "runtime_link_absent"

    return ConstantImpact(
        compile_impact=compile_impact,
        runtime_link_impact=runtime_impact,
        old_field_has_constant_value=bool(old_field_has_constant_value),
        source_reference_present=bool(source_reference_present),
        runtime_field_edge_present=bool(runtime_field_edge_present),
        source_artifact_aligned=bool(source_artifact_aligned),
    )


def _javap(classpath, *args):
    completed = subprocess.run(
        ["javap", "-classpath", str(Path(classpath)), *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"javap_failed:{completed.stderr.strip()}")
    return completed.stdout


def javap_field_has_constant_value(classpath, owner, field_name):
    lines = _javap(classpath, "-verbose", "-p", owner).splitlines()
    declaration = re.compile(rf"\b{re.escape(field_name)};$")
    in_field = False
    for line in lines:
        stripped = line.strip()
        if declaration.search(stripped):
            in_field = True
            continue
        if not in_field:
            continue
        if stripped.startswith("ConstantValue:"):
            return True
        if stripped == "}" or (line.startswith("  ") and not line.startswith("    ") and stripped.endswith(";")):
            return False
    return False


def javap_caller_has_field_link(classpath, caller, owner, field_name):
    output = _javap(classpath, "-c", "-p", caller)
    owner_path = str(owner).replace(".", "/")
    return bool(re.search(
        rf"//\s+Field\s+{re.escape(owner_path)}\.{re.escape(field_name)}:",
        output,
    ))

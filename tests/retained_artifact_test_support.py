import csv
import hashlib
import sys
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import s1_dep_diff


def retain_current_artifact_contract(report_dir, artifact_path, rows=None):
    """Create the Step1 retained-artifact contract used by Step4/Step5 tests."""
    report_dir = Path(report_dir)
    artifact_path = Path(artifact_path)
    dependencies = report_dir / "evidence" / "dependencies"
    dependencies.mkdir(parents=True, exist_ok=True)
    if rows is None:
        current_csv = dependencies / "deps_current_resolved.csv"
        with current_csv.open(encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
    return s1_dep_diff.materialize_changed_dependency_jars(
        [],
        {
            "current": {
                "artifact_path": str(artifact_path),
                "artifact_sha256": hashlib.sha256(
                    artifact_path.read_bytes()
                ).hexdigest(),
            }
        },
        dependencies,
        current_entries=list(rows or ()),
    )

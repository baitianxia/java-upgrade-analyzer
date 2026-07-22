#!/usr/bin/env python3
"""Build and run deterministic unittest profiles from capability-family metadata."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import sys
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
TEST_FIELDS = ("positive_tests", "negative_tests", "mutation_tests")


def _load_json(path: Path) -> dict:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"json_not_object:{path}")
    return payload


def _flatten_suite(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _flatten_suite(item)
        else:
            yield item


def resolve_test_reference(reference: str) -> tuple[list[str], str]:
    try:
        suite = unittest.defaultTestLoader.loadTestsFromName(reference)
    except (AttributeError, ImportError, TypeError, ValueError) as exc:
        return [], f"unloadable_test_reference:{reference}:{type(exc).__name__}"
    tests = list(_flatten_suite(suite))
    if not tests or any(type(test).__name__ == "_FailedTest" for test in tests):
        return [], f"unloadable_test_reference:{reference}"
    return sorted({test.id() for test in tests}), ""


def validate_capability_references(registry: dict) -> list[str]:
    errors = []
    for family in registry.get("families") or []:
        if not isinstance(family, dict) or family.get("state") != "enforced":
            continue
        family_id = str(family.get("family_id") or "")
        for field in TEST_FIELDS:
            references = family.get(field)
            if not isinstance(references, list) or not references:
                errors.append(f"missing_{field}:{family_id}")
                continue
            for reference in references:
                _tests, error = resolve_test_reference(str(reference))
                if error:
                    errors.append(f"{family_id}:{error}")
    return sorted(errors)


def build_profile_catalog(registry: dict, manifest: dict, profile: str) -> dict:
    if registry.get("schema_version") != 1:
        raise ValueError("unsupported_capability_registry_schema")
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported_test_profile_schema")
    profiles = manifest.get("profiles") or {}
    config = profiles.get(profile)
    if not isinstance(config, dict):
        raise ValueError(f"unknown_test_profile:{profile}")
    families = {
        str(item.get("family_id") or ""): item
        for item in registry.get("families") or []
        if isinstance(item, dict)
    }
    references = []
    selected_families = []
    roles = tuple(config.get("roles") or TEST_FIELDS)
    if any(role not in TEST_FIELDS for role in roles):
        raise ValueError(f"invalid_test_role:{profile}")
    for family_id in config.get("capability_families") or []:
        family = families.get(str(family_id))
        if family is None:
            raise ValueError(f"unknown_capability_family:{profile}:{family_id}")
        selected_families.append(str(family_id))
        for role in roles:
            references.extend(family.get(role) or [])
    references.extend(config.get("include") or [])
    references = list(dict.fromkeys(str(item) for item in references if str(item).strip()))
    test_ids = []
    errors = []
    for reference in references:
        resolved, error = resolve_test_reference(reference)
        test_ids.extend(resolved)
        if error:
            errors.append(error)
    return {
        "profile": profile,
        "capability_families": selected_families,
        "references": references,
        "test_ids": sorted(set(test_ids)),
        "errors": sorted(errors),
        "repeat": max(1, int(config.get("repeat") or 1)),
        "max_test_seconds": float(config.get("max_test_seconds") or 0.0),
        "declared_shards": max(1, int(config.get("shards") or 1)),
    }


def shard_test_ids(test_ids, shard_index: int, shard_count: int) -> list[str]:
    if shard_count < 1 or shard_index < 0 or shard_index >= shard_count:
        raise ValueError("invalid_test_shard")
    return [
        test_id for test_id in sorted(test_ids)
        if int(hashlib.sha256(test_id.encode("utf-8")).hexdigest(), 16) % shard_count
        == shard_index
    ]


class _TimingResult(unittest.TextTestResult):
    def startTest(self, test):
        self._started_at = time.perf_counter()
        super().startTest(test)

    def stopTest(self, test):
        elapsed = time.perf_counter() - self._started_at
        self.durations[test.id()] = round(elapsed, 6)
        super().stopTest(test)

    def addSuccess(self, test):
        self.outcomes[test.id()] = "passed"
        super().addSuccess(test)

    def addFailure(self, test, err):
        self.outcomes[test.id()] = "failed"
        super().addFailure(test, err)

    def addError(self, test, err):
        self.outcomes[test.id()] = "error"
        super().addError(test, err)

    def addSkip(self, test, reason):
        self.outcomes[test.id()] = "skipped"
        super().addSkip(test, reason)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.durations = {}
        self.outcomes = {}


def run_catalog(test_ids, *, repeat=1, max_test_seconds=0.0, stream=None) -> dict:
    histories = {test_id: [] for test_id in test_ids}
    duration_totals = {test_id: 0.0 for test_id in test_ids}
    run_errors = []
    for repetition in range(max(1, int(repeat))):
        suite = unittest.defaultTestLoader.loadTestsFromNames(list(test_ids))
        result = unittest.TextTestRunner(
            stream=stream or sys.stderr,
            verbosity=1,
            resultclass=_TimingResult,
        ).run(suite)
        for test_id in test_ids:
            outcome = result.outcomes.get(test_id, "not_run")
            histories[test_id].append(outcome)
            duration_totals[test_id] += result.durations.get(test_id, 0.0)
        if not result.wasSuccessful():
            run_errors.append(f"test_run_failed:{repetition + 1}")

    durations = [
        {
            "test_id": test_id,
            "total_seconds": round(duration_totals[test_id], 6),
            "mean_seconds": round(duration_totals[test_id] / max(1, repeat), 6),
        }
        for test_id in test_ids
    ]
    durations.sort(key=lambda item: (-item["mean_seconds"], item["test_id"]))
    flaky = sorted(
        test_id for test_id, outcomes in histories.items()
        if len(set(outcomes)) > 1
    )
    slow = [
        item for item in durations
        if max_test_seconds > 0 and item["mean_seconds"] > max_test_seconds
    ]
    return {
        "status": "passed" if not run_errors and not flaky and not slow else "failed",
        "test_count": len(test_ids),
        "repeat": repeat,
        "outcomes": histories,
        "duration_ranking": durations,
        "flaky_tests": flaky,
        "slow_tests": slow,
        "errors": run_errors,
    }


def _write_json(path: str, payload: dict):
    if not path:
        return
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", default="tests/fixtures/capability_families.json")
    parser.add_argument("--manifest", default="tests/fixtures/test_profiles.json")
    parser.add_argument("--profile", default="quick")
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--shard-index", type=int, default=None)
    parser.add_argument("--shard-count", type=int, default=None)
    parser.add_argument("--json-out", default="")
    args = parser.parse_args(argv)

    registry = _load_json(ROOT / args.registry)
    manifest = _load_json(ROOT / args.manifest)
    catalog = build_profile_catalog(registry, manifest, args.profile)
    errors = validate_capability_references(registry) + list(catalog["errors"])
    test_ids = list(catalog["test_ids"])
    shard_count = args.shard_count or 1
    shard_index = args.shard_index or 0
    if args.shard_index is not None or args.shard_count is not None:
        test_ids = shard_test_ids(test_ids, shard_index, shard_count)
    payload = {
        **catalog,
        "selected_test_ids": test_ids,
        "shard_index": shard_index,
        "shard_count": shard_count,
        "registry_errors": sorted(errors),
    }
    if errors or not test_ids:
        payload["status"] = "failed"
    elif args.validate_only:
        payload["status"] = "passed"
    else:
        payload["run"] = run_catalog(
            test_ids,
            repeat=catalog["repeat"],
            max_test_seconds=catalog["max_test_seconds"],
        )
        payload["status"] = payload["run"]["status"]
    _write_json(args.json_out, payload)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if payload["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

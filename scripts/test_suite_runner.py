#!/usr/bin/env python3
"""Discover once, classify deterministically, and run one governed test suite."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time
import unittest
from typing import Any, Iterable, Mapping

from test_trust_gate import run_trust_gate


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "tests" / "fixtures" / "test_suite_policy.json"
SUITES = ("blackbox", "whitebox", "performance", "all")


def load_policy(path: str | Path = DEFAULT_POLICY) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def iter_tests(suite: unittest.TestSuite) -> Iterable[unittest.TestCase]:
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from iter_tests(item)
        else:
            yield item


def blackbox_prefixes(policy: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(
        str(root).strip("/").replace("/", ".")
        for root in policy.get("blackbox_test_roots") or ()
    )


def _matches(test_id: str, selector: str) -> bool:
    normalized = selector.rstrip(".")
    return test_id == normalized or test_id.startswith(normalized + ".")


def classify_test_id(test_id: str, policy: Mapping[str, Any]) -> str:
    blackbox = any(
        _matches(test_id, prefix) for prefix in blackbox_prefixes(policy)
    )
    performance = any(
        _matches(test_id, str(selector))
        for selector in policy.get("performance_test_selectors") or ()
    )
    if blackbox and performance:
        raise ValueError(f"overlapping test-suite selectors: {test_id}")
    if blackbox:
        return "blackbox"
    if performance:
        return "performance"
    return "whitebox"


def discover_tests(
    repository_root: str | Path = ROOT,
    *,
    start_directory: str | Path = "tests",
) -> list[unittest.TestCase]:
    root = Path(repository_root).resolve()
    start = Path(start_directory)
    if not start.is_absolute():
        start = root / start
    discovered = unittest.defaultTestLoader.discover(
        str(start), pattern="test*.py", top_level_dir=str(root)
    )
    return list(iter_tests(discovered))


def load_performance_tests(
    policy: Mapping[str, Any],
    repository_root: str | Path = ROOT,
) -> list[unittest.TestCase]:
    root_text = str(Path(repository_root).resolve())
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    loaded = unittest.defaultTestLoader.loadTestsFromNames([
        str(selector)
        for selector in policy.get("performance_test_selectors") or ()
    ])
    unique: dict[str, unittest.TestCase] = {}
    for test in iter_tests(loaded):
        unique.setdefault(test.id(), test)
    return list(unique.values())


def partition_tests(
    tests: Iterable[unittest.TestCase], policy: Mapping[str, Any],
) -> dict[str, list[unittest.TestCase]]:
    partitions: dict[str, list[unittest.TestCase]] = {
        "blackbox": [], "whitebox": [], "performance": [],
    }
    for test in tests:
        partitions[classify_test_id(test.id(), policy)].append(test)
    return partitions


def _selector_gaps(
    tests: Iterable[unittest.TestCase], policy: Mapping[str, Any],
) -> list[str]:
    ids = [test.id() for test in tests]
    return [
        str(selector)
        for selector in policy.get("performance_test_selectors") or ()
        if not any(_matches(test_id, str(selector)) for test_id in ids)
    ]


def skips_are_forbidden(suite_name: str) -> bool:
    return suite_name in {"blackbox", "performance"}


def skipped_test_is_forbidden(
    suite_name: str, test_id: str, policy: Mapping[str, Any],
) -> bool:
    if skips_are_forbidden(suite_name):
        return True
    return (
        suite_name == "all"
        and classify_test_id(test_id, policy) in {"blackbox", "performance"}
    )


def public_capability_readiness_blocks(
    suite_name: str, trust_result: Mapping[str, Any],
) -> bool:
    """Only a full/release run may claim system-wide readiness."""
    return (
        suite_name == "all"
        and (trust_result.get("capability_readiness") or {}).get("status")
        != "complete"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a governed test suite")
    parser.add_argument("--suite", choices=SUITES, required=True)
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--policy", default="")
    parser.add_argument("--json-out", default="")
    parser.add_argument("--verbosity", type=int, choices=(0, 1, 2), default=1)
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    policy_path = Path(args.policy).resolve() if args.policy else (
        root / "tests" / "fixtures" / "test_suite_policy.json"
    )
    started_at = datetime.now(timezone.utc)
    started = time.monotonic()
    trust = run_trust_gate(root, policy_path)
    if trust.get("status") != "passed":
        payload = {
            "schema": "java-upgrade-analyzer.test-suite-run.v1",
            "suite": args.suite,
            "status": "failed",
            "reason_code": "TEST_TRUST_GATE_FAILED",
            "trust": trust,
            "started_at": started_at.isoformat(),
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
        print(json.dumps(payload, ensure_ascii=False))
        return 2

    try:
        policy = load_policy(policy_path)
        if args.suite == "blackbox":
            discovered = discover_tests(root, start_directory="tests/blackbox")
        elif args.suite == "performance":
            discovered = load_performance_tests(policy, root)
        else:
            discovered = discover_tests(root)
        partitions = partition_tests(discovered, policy)
    except Exception as error:  # noqa: BLE001 - emit a stable runner failure
        payload = {
            "schema": "java-upgrade-analyzer.test-suite-run.v1",
            "suite": args.suite,
            "status": "failed",
            "reason_code": "TEST_DISCOVERY_OR_CLASSIFICATION_FAILED",
            "detail": f"{type(error).__name__}: {error}",
            "trust": trust,
        }
        print(json.dumps(payload, ensure_ascii=False))
        return 2

    selector_gaps = (
        _selector_gaps(discovered, policy)
        if args.suite in {"performance", "all"}
        else []
    )
    selected = discovered if args.suite == "all" else partitions[args.suite]
    if not selected or selector_gaps:
        payload = {
            "schema": "java-upgrade-analyzer.test-suite-run.v1",
            "suite": args.suite,
            "status": "failed",
            "reason_code": (
                "TEST_SUITE_EMPTY" if not selected
                else "PERFORMANCE_SELECTOR_MATCHES_NO_TEST"
            ),
            "selector_gaps": selector_gaps,
            "counts": {key: len(value) for key, value in partitions.items()},
            "trust": trust,
        }
        print(json.dumps(payload, ensure_ascii=False))
        return 2

    print(
        f"[test-suite] suite={args.suite} selected={len(selected)} "
        f"blackbox={len(partitions['blackbox'])} "
        f"whitebox={len(partitions['whitebox'])} "
        f"performance={len(partitions['performance'])}",
        flush=True,
    )
    result = unittest.TextTestRunner(verbosity=args.verbosity).run(
        unittest.TestSuite(selected)
    )
    skips = [
        {"test_id": test.id(), "reason": reason}
        for test, reason in result.skipped
    ]
    unexpected_skips = [
        item for item in skips
        if skipped_test_is_forbidden(args.suite, item["test_id"], policy)
    ]
    capability_readiness_blocked = public_capability_readiness_blocks(
        args.suite, trust,
    )
    successful = (
        result.wasSuccessful()
        and not unexpected_skips
        and not capability_readiness_blocked
    )
    payload = {
        "schema": "java-upgrade-analyzer.test-suite-run.v1",
        "suite": args.suite,
        "status": "passed" if successful else "failed",
        "reason_code": (
            "TEST_SUITE_UNEXPECTED_SKIP"
            if unexpected_skips else
            "PUBLIC_CAPABILITY_MATRIX_INCOMPLETE"
            if capability_readiness_blocked else
            "TEST_SUITE_FAILED" if not result.wasSuccessful() else
            "TEST_SUITE_PASSED"
        ),
        "counts": {
            **{key: len(value) for key, value in partitions.items()},
            "discovered": len(discovered),
            "selected": len(selected),
            "run": result.testsRun,
            "failures": len(result.failures),
            "errors": len(result.errors),
            "skipped": len(result.skipped),
            "expected_failures": len(result.expectedFailures),
            "unexpected_successes": len(result.unexpectedSuccesses),
        },
        "discovery_scope": (
            "tests/blackbox" if args.suite == "blackbox"
            else "performance_selectors" if args.suite == "performance"
            else "tests"
        ),
        "skip_policy": (
            "forbidden" if skips_are_forbidden(args.suite)
            else "blackbox_and_performance_forbidden" if args.suite == "all"
            else "reported"
        ),
        "skips": skips,
        "unexpected_skips": unexpected_skips,
        "capability_readiness_blocked": capability_readiness_blocked,
        "capability_readiness": trust.get("capability_readiness"),
        "trust": trust,
        "duration_seconds": round(time.monotonic() - started, 6),
        "started_at": started_at.isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }
    if args.json_out:
        target = Path(args.json_out).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(payload, ensure_ascii=False))
    return 0 if successful else 1


if __name__ == "__main__":
    raise SystemExit(main())

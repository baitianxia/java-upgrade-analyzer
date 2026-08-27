#!/usr/bin/env python3
"""Run explicit unittest selectors and persist auditable execution evidence."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time
import unittest
from typing import Any, Iterable

from compat import setup_utf8_io


setup_utf8_io()

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def iter_tests(suite: unittest.TestSuite) -> Iterable[unittest.TestCase]:
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from iter_tests(item)
        else:
            yield item


def _test_id(test: Any) -> str:
    try:
        return str(test.id())
    except Exception:  # noqa: BLE001 - evidence must survive broken test objects
        return f"{type(test).__module__}.{type(test).__qualname__}"


def _outcomes(rows: Iterable[tuple[Any, str]]) -> list[dict[str, str]]:
    return [
        {"test_id": _test_id(test), "detail": str(detail)[-8000:]}
        for test, detail in rows
    ]


def _write_payload(payload: dict[str, Any], target: str) -> None:
    if not target:
        return
    path = Path(target).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run unittest selectors with structured execution evidence"
    )
    parser.add_argument("--suite-label", required=True)
    parser.add_argument("--json-out", default="")
    parser.add_argument(
        "--forbid-skips",
        action="store_true",
        help="fail when any selected test is skipped",
    )
    parser.add_argument(
        "--allow-skip",
        action="append",
        default=[],
        help="exact selected test id allowed to skip; all other skips fail",
    )
    parser.add_argument("--verbosity", type=int, choices=(0, 1, 2), default=1)
    parser.add_argument("selectors", nargs="+")
    args = parser.parse_args(argv)

    started_at = datetime.now(timezone.utc)
    started = time.monotonic()
    try:
        loaded = unittest.defaultTestLoader.loadTestsFromNames(args.selectors)
        selected = list(iter_tests(loaded))
        unique_selected: dict[str, unittest.TestCase] = {}
        duplicate_selections: list[str] = []
        for test in selected:
            test_id = _test_id(test)
            if test_id in unique_selected:
                duplicate_selections.append(test_id)
            else:
                unique_selected[test_id] = test
        loader_failures = [
            _test_id(test) for test in selected
            if test.__class__.__name__ == "_FailedTest"
        ]
        result = unittest.TextTestRunner(verbosity=args.verbosity).run(
            unittest.TestSuite(unique_selected.values())
        )
        allowed_skips = [str(value).strip() for value in args.allow_skip]
        allowed_skip_set = set(allowed_skips)
        skip_allowlist_invalid = (
            len(allowed_skips) != len(allowed_skip_set)
            or not allowed_skip_set.issubset(unique_selected)
        )
        unexpected_skips = [
            {"test_id": _test_id(test), "reason": str(reason)}
            for test, reason in result.skipped
            if _test_id(test) not in allowed_skip_set
        ] if args.forbid_skips or allowed_skip_set else []
        successful = (
            result.wasSuccessful()
            and result.testsRun > 0
            and not duplicate_selections
            and not skip_allowlist_invalid
            and not result.expectedFailures
            and not unexpected_skips
        )
        reason_code = (
            "UNITTEST_SELECTION_EMPTY" if result.testsRun == 0
            else "UNITTEST_LOAD_FAILED" if loader_failures
            else "UNITTEST_SELECTION_OVERLAP" if duplicate_selections
            else "UNITTEST_SKIP_ALLOWLIST_INVALID" if skip_allowlist_invalid
            else "UNITTEST_EXPECTED_FAILURE" if result.expectedFailures
            else "UNITTEST_UNEXPECTED_SKIP" if unexpected_skips
            else "UNITTEST_RUN_FAILED" if not result.wasSuccessful()
            else "UNITTEST_RUN_PASSED"
        )
        payload = {
            "schema": "java-upgrade-analyzer.unittest-execution.v1",
            "suite_label": args.suite_label,
            "status": "passed" if successful else "failed",
            "reason_code": reason_code,
            "selectors": args.selectors,
            "counts": {
                "selected": len(selected),
                "unique_selected": len(unique_selected),
                "duplicate_selections": len(duplicate_selections),
                "run": result.testsRun,
                "failures": len(result.failures),
                "errors": len(result.errors),
                "skipped": len(result.skipped),
                "expected_failures": len(result.expectedFailures),
                "unexpected_successes": len(result.unexpectedSuccesses),
                "loader_failures": len(loader_failures),
            },
            "loader_failures": loader_failures,
            "duplicate_selections": duplicate_selections,
            "failures": _outcomes(result.failures),
            "errors": _outcomes(result.errors),
            "expected_failures": _outcomes(result.expectedFailures),
            "skips": [
                {"test_id": _test_id(test), "reason": str(reason)}
                for test, reason in result.skipped
            ],
            "unexpected_skips": unexpected_skips,
            "allowed_skip_selectors": allowed_skips,
            "unexpected_successes": [
                _test_id(test) for test in result.unexpectedSuccesses
            ],
            "skip_policy": (
                "allowlisted_only" if allowed_skips
                else "forbidden" if args.forbid_skips else "reported"
            ),
            "duration_seconds": round(time.monotonic() - started, 6),
            "started_at": started_at.isoformat(),
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
    except BaseException as error:  # noqa: BLE001 - persist infrastructure failure
        payload = {
            "schema": "java-upgrade-analyzer.unittest-execution.v1",
            "suite_label": args.suite_label,
            "status": "failed",
            "reason_code": "UNITTEST_RUNNER_INFRASTRUCTURE_FAILED",
            "selectors": args.selectors,
            "counts": {
                "selected": 0,
                "unique_selected": 0,
                "duplicate_selections": 0,
                "run": 0,
                "failures": 0,
                "errors": 1,
                "skipped": 0,
                "expected_failures": 0,
                "unexpected_successes": 0,
                "loader_failures": 0,
            },
            "duplicate_selections": [],
            "loader_failures": [],
            "failures": [],
            "errors": [],
            "expected_failures": [],
            "skips": [],
            "unexpected_skips": [],
            "allowed_skip_selectors": [
                str(value).strip() for value in args.allow_skip
            ],
            "unexpected_successes": [],
            "skip_policy": (
                "allowlisted_only" if args.allow_skip
                else "forbidden" if args.forbid_skips else "reported"
            ),
            "detail": f"{type(error).__name__}: {error}",
            "duration_seconds": round(time.monotonic() - started, 6),
            "started_at": started_at.isoformat(),
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
    try:
        _write_payload(payload, args.json_out)
    except (OSError, UnicodeError, TypeError, ValueError) as error:
        payload["status"] = "failed"
        payload["reason_code"] = "UNITTEST_EVIDENCE_WRITE_FAILED"
        payload["evidence_write_detail"] = f"{type(error).__name__}: {error}"
    print(json.dumps(payload, ensure_ascii=False))
    return 0 if payload["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

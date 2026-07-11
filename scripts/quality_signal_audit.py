#!/usr/bin/env python3
"""Audit quality signals that are easy to miss in passing regression runs.

The real-project matrix intentionally has non-gating probes because grep-based
baselines cannot always distinguish overloads or comments. Those probes are
useful, but dangerous if humans only read "passed". This script turns the
"passed but suspicious" facts into explicit signals.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import sys


@dataclass(frozen=True)
class QualitySignal:
    signal_type: str
    severity: str
    blocking: bool
    case: str
    kind: str = ""
    step: str = ""
    symbol: str = ""
    message: str = ""
    count: int = 0
    expected: str = ""
    actual: str = ""
    evidence: tuple[str, ...] = ()
    fixture_status: str = ""
    notes: str = ""
    reason_code: str = ""
    symbol_kind: str = ""
    sample_symbols: tuple[str, ...] = ()


LEGACY_KIND_TO_TYPE = {
    "real_project_skipped": "infra_skip",
    "gating_production_missing": "correctness_failure",
    "non_gating_production_missing": "capability_gap",
    "non_gating_missing_explanation": "evidence_weakness",
}

LEGACY_SEVERITY_TO_P = {
    "high": "P1",
    "medium": "P2",
    "low": "P3",
}


def _default_blocking(signal_type: str, severity: str) -> bool:
    if severity == "P0":
        return True
    if severity == "P1" and signal_type in {
        "correctness_failure",
        "capability_gap",
        "evidence_weakness",
        "performance_regression",
        "project_asset_invalid",
        "coverage_gap",
        "test_configuration_failure",
        "ground_truth_insufficient",
        "conclusion_gap",
    }:
        return True
    return False


def normalize_signal(raw: dict, default_case: str = "") -> QualitySignal:
    legacy_kind = str(raw.get("kind") or "")
    signal_type = str(
        raw.get("signal_type")
        or LEGACY_KIND_TO_TYPE.get(legacy_kind)
        or legacy_kind
        or "evidence_weakness"
    )
    severity = str(raw.get("severity") or "P2")
    severity = LEGACY_SEVERITY_TO_P.get(severity, severity)
    evidence = raw.get("evidence") or ()
    if isinstance(evidence, str):
        evidence = (evidence,)
    else:
        evidence = tuple(str(item) for item in evidence)
    sample_symbols = raw.get("sample_symbols") or ()
    if isinstance(sample_symbols, str):
        sample_symbols = (sample_symbols,)
    else:
        sample_symbols = tuple(str(item) for item in sample_symbols)
    blocking = raw.get("blocking")
    if blocking is None:
        blocking = _default_blocking(signal_type, severity)
    return QualitySignal(
        signal_type=signal_type,
        severity=severity,
        blocking=bool(blocking),
        case=str(raw.get("case") or default_case),
        kind=legacy_kind or str(raw.get("kind") or ""),
        step=str(raw.get("step") or ""),
        symbol=str(raw.get("symbol") or ""),
        message=str(raw.get("message") or ""),
        count=int(raw.get("count") or 0),
        expected=str(raw.get("expected") or ""),
        actual=str(raw.get("actual") or ""),
        evidence=evidence,
        fixture_status=str(raw.get("fixture_status") or ""),
        notes=str(raw.get("notes") or ""),
        reason_code=str(raw.get("reason_code") or ""),
        symbol_kind=str(raw.get("symbol_kind") or ""),
        sample_symbols=sample_symbols,
    )


def _load_payload(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _extract_results(payload: dict) -> list[dict]:
    if isinstance(payload.get("results"), list):
        return payload.get("results") or []
    if isinstance(payload.get("real_project_results"), list):
        return payload.get("real_project_results") or []
    if payload.get("case"):
        return [payload]
    return []


def audit_real_project_payload(payload: dict) -> list[QualitySignal]:
    signals: list[QualitySignal] = []
    for result in _extract_results(payload):
        case = str(result.get("case") or "")
        explicit_signal_count = 0
        for raw_signal in result.get("quality_signals") or []:
            signals.append(normalize_signal(raw_signal, default_case=case))
            explicit_signal_count += 1
        status = str(result.get("status") or "")
        if status == "skipped":
            if not explicit_signal_count:
                signals.append(
                    normalize_signal({
                        "severity": "high",
                        "kind": "real_project_skipped",
                        "case": case,
                        "message": str(result.get("reason") or "real project regression skipped"),
                    })
                )
            continue
        if status == "observed" and not explicit_signal_count:
            signals.append(normalize_signal({
                "signal_type": "ground_truth_insufficient",
                "severity": "P1",
                "case": case,
                "message": "real project result is observed and has no reviewed ground truth",
            }))
            continue
        if explicit_signal_count:
            continue

        summary = result.get("summary") or {}
        for field in ("uncertain", "not_analyzed", "not_found_in_static_analysis"):
            count = int(summary.get(field) or 0)
            if count:
                signals.append(
                    normalize_signal({
                        "severity": "medium",
                        "kind": f"summary_{field}",
                        "case": case,
                        "count": count,
                        "message": f"{case} summary has {count} {field} item(s)",
                    })
                )

        for check in result.get("checks") or []:
            prod_missing = int(check.get("production_missing") or 0)
            symbol = str(check.get("symbol") or "")
            gating = bool(check.get("gating"))
            notes = str(check.get("notes") or "")
            if prod_missing and gating:
                signals.append(
                    normalize_signal({
                        "severity": "high",
                        "kind": "gating_production_missing",
                        "case": case,
                        "symbol": symbol,
                        "count": prod_missing,
                        "notes": notes,
                        "message": f"{case}:{symbol} missing {prod_missing} gated production baseline file(s)",
                    })
                )
            elif prod_missing:
                signals.append(
                    normalize_signal({
                        "severity": "medium",
                        "kind": "non_gating_production_missing",
                        "case": case,
                        "symbol": symbol,
                        "count": prod_missing,
                        "notes": notes,
                        "message": (
                            f"{case}:{symbol} has {prod_missing} non-gating production baseline miss(es); "
                            "review whether the probe is too broad or the analyzer missed a real case"
                        ),
                    })
                )
            if not gating and prod_missing and not notes:
                signals.append(
                    normalize_signal({
                        "severity": "medium",
                        "kind": "non_gating_missing_explanation",
                        "case": case,
                        "symbol": symbol,
                        "count": prod_missing,
                        "message": f"{case}:{symbol} is non-gating with production misses but has no notes",
                    })
                )
    return signals


def summarize_signals(signals: list[QualitySignal]) -> dict:
    by_severity: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for signal in signals:
        by_severity[signal.severity] = by_severity.get(signal.severity, 0) + 1
        if signal.kind:
            by_kind[signal.kind] = by_kind.get(signal.kind, 0) + 1
        by_type[signal.signal_type] = by_type.get(signal.signal_type, 0) + 1
    return {
        "signal_count": len(signals),
        "blocking_signals": sum(1 for signal in signals if signal.blocking),
        "non_blocking_signals": sum(1 for signal in signals if not signal.blocking),
        "fixture_debt": sum(
            1 for signal in signals
            if signal.blocking and signal.fixture_status in {"", "missing"}
        ),
        "by_severity": dict(sorted(by_severity.items())),
        "by_type": dict(sorted(by_type.items())),
        "by_kind": dict(sorted(by_kind.items())),
    }


def _write_json(path: str, payload: dict) -> None:
    if not path:
        return
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Audit non-obvious quality signals from real project regressions")
    parser.add_argument("json_file", nargs="+", help="JSON output from real_project_regression.py --json")
    parser.add_argument("--strict", action="store_true", help="Fail when any signal is present")
    parser.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Fail only when high severity signals are present",
    )
    parser.add_argument(
        "--fail-on-blocking",
        action="store_true",
        help="Fail when any canonical blocking signal is present",
    )
    parser.add_argument("--json-out", default="", help="Write structured audit result to JSON")
    args = parser.parse_args(argv)

    signals: list[QualitySignal] = []
    for raw_path in args.json_file:
        signals.extend(audit_real_project_payload(_load_payload(Path(raw_path))))

    payload = {
        "status": "signals_found" if signals else "clean",
        "summary": summarize_signals(signals),
        "signals": [asdict(signal) for signal in signals],
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    _write_json(args.json_out, payload)

    if args.strict and signals:
        return 1
    if args.fail_on_high and any(signal.severity in {"high", "P0", "P1"} for signal in signals):
        return 1
    if args.fail_on_blocking and any(signal.blocking for signal in signals):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

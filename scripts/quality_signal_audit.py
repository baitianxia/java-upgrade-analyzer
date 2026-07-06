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
    severity: str
    kind: str
    case: str
    symbol: str = ""
    message: str = ""
    count: int = 0
    notes: str = ""


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
        status = str(result.get("status") or "")
        if status == "skipped":
            signals.append(
                QualitySignal(
                    severity="high",
                    kind="real_project_skipped",
                    case=case,
                    message=str(result.get("reason") or "real project regression skipped"),
                )
            )
            continue

        summary = result.get("summary") or {}
        for field in ("uncertain", "not_analyzed", "not_found_in_static_analysis"):
            count = int(summary.get(field) or 0)
            if count:
                signals.append(
                    QualitySignal(
                        severity="medium",
                        kind=f"summary_{field}",
                        case=case,
                        count=count,
                        message=f"{case} summary has {count} {field} item(s)",
                    )
                )

        for check in result.get("checks") or []:
            prod_missing = int(check.get("production_missing") or 0)
            symbol = str(check.get("symbol") or "")
            gating = bool(check.get("gating"))
            notes = str(check.get("notes") or "")
            if prod_missing and gating:
                signals.append(
                    QualitySignal(
                        severity="high",
                        kind="gating_production_missing",
                        case=case,
                        symbol=symbol,
                        count=prod_missing,
                        notes=notes,
                        message=f"{case}:{symbol} missing {prod_missing} gated production baseline file(s)",
                    )
                )
            elif prod_missing:
                signals.append(
                    QualitySignal(
                        severity="medium",
                        kind="non_gating_production_missing",
                        case=case,
                        symbol=symbol,
                        count=prod_missing,
                        notes=notes,
                        message=(
                            f"{case}:{symbol} has {prod_missing} non-gating production baseline miss(es); "
                            "review whether the probe is too broad or the analyzer missed a real case"
                        ),
                    )
                )
            if not gating and prod_missing and not notes:
                signals.append(
                    QualitySignal(
                        severity="medium",
                        kind="non_gating_missing_explanation",
                        case=case,
                        symbol=symbol,
                        count=prod_missing,
                        message=f"{case}:{symbol} is non-gating with production misses but has no notes",
                    )
                )
    return signals


def summarize_signals(signals: list[QualitySignal]) -> dict:
    by_severity: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    for signal in signals:
        by_severity[signal.severity] = by_severity.get(signal.severity, 0) + 1
        by_kind[signal.kind] = by_kind.get(signal.kind, 0) + 1
    return {
        "signal_count": len(signals),
        "by_severity": dict(sorted(by_severity.items())),
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
    if args.fail_on_high and any(signal.severity == "high" for signal in signals):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

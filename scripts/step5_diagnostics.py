#!/usr/bin/env python3
"""Incremental Step5 diagnostics for long-running analysis.

The final ``summary.json`` remains the conclusion artifact.  This module owns a
small append-only observability ledger so failures are visible when they are
discovered instead of only after every API has been traced and rendered.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from diagnostic_contract import canonical_reason_code, normalize_diagnostic_payload
from progress_logging import emit_progress


STEP5_DIAGNOSTICS_SCHEMA = "java-upgrade-analyzer.step5-diagnostics.v1"
_SAMPLE_LIMIT = 5


def _failure_sample(failure):
    return {
        "stage": str(getattr(failure, "stage", "") or ""),
        "artifact": str(getattr(failure, "artifact", "") or ""),
        "class_name": str(getattr(failure, "class_name", "") or ""),
        "api_identity": str(getattr(failure, "api_identity", "") or ""),
        "detail": str(getattr(failure, "detail", "") or "")[:1000],
    }


class Step5DiagnosticRecorder:
    """Write bounded, immediately readable Step5 diagnostic events."""

    def __init__(self, report_dir, *, reset=True):
        self.report_dir = Path(report_dir).resolve()
        self.path = (
            self.report_dir
            / ".runtime"
            / "observability"
            / "step5_diagnostics.jsonl"
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if reset:
            self.path.write_text("", encoding="utf-8")
        self._trace_reason_counts = Counter()

    def record(
        self,
        *,
        phase,
        reason_code,
        blocking,
        scope,
        message,
        status="detected",
        failure_count=1,
        occurrence_count=0,
        collectors=(),
        samples=(),
        current=None,
        total=None,
    ):
        canonical = canonical_reason_code(reason_code)
        payload = normalize_diagnostic_payload(
            {
                "schema": STEP5_DIAGNOSTICS_SCHEMA,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": str(status or "detected"),
                "phase": str(phase or ""),
                "reason_code": canonical,
                "blocking": bool(blocking),
                "scope": str(scope or "unknown"),
                "message": str(message or ""),
                "failure_count": int(failure_count or 0),
                "occurrence_count": int(occurrence_count or 0),
                "collectors": sorted({
                    str(value or "").strip()
                    for value in collectors or ()
                    if str(value or "").strip()
                }),
                "samples": list(samples or ())[:_SAMPLE_LIMIT],
                "current": current,
                "total": total,
            },
            origin_step="step5",
        )
        try:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n"
                )
                handle.flush()
        except (OSError, TypeError, ValueError):
            # Observability must not replace the analyzer's actual failure.
            pass
        emit_progress(
            "step5",
            "diagnostic",
            (
                f"{canonical}: {message} "
                f"（scope={payload['scope']}，count={payload['failure_count']}）"
            ),
            current=current,
            total=total,
            report_dir=self.report_dir,
        )
        return payload

    def record_collector_failures(self, phase, collector_batches):
        grouped = defaultdict(list)
        for batch in collector_batches or ():
            collector = str(getattr(batch, "collector", "") or "unknown")
            for failure in getattr(batch, "failures", ()) or ():
                key = (
                    canonical_reason_code(getattr(failure, "reason_code", "")),
                    bool(getattr(failure, "blocking", False)),
                    str(getattr(failure, "scope", "") or "global"),
                )
                grouped[key].append((collector, failure))

        events = []
        for (reason_code, blocking, scope), failures in sorted(grouped.items()):
            occurrence_count = sum(
                len(getattr(failure, "occurrences", ()) or ())
                for _collector, failure in failures
            )
            events.append(self.record(
                phase=phase,
                reason_code=reason_code,
                blocking=blocking,
                scope=scope,
                message="分析器已发现覆盖失败，已立即记录；最终影响范围仍按失败作用域收敛。",
                failure_count=len(failures),
                occurrence_count=occurrence_count,
                collectors=[collector for collector, _failure in failures],
                samples=[
                    _failure_sample(failure)
                    for _collector, failure in failures[:_SAMPLE_LIMIT]
                ],
            ))
        return events

    def record_trace_result(self, result, current, total):
        status = str(getattr(result, "analysis_status", "") or "")
        reason_code = canonical_reason_code(
            getattr(result, "reason_code", "") or "UNKNOWN"
        )
        if status not in {"uncertain", "not_analyzed"}:
            return
        key = (status, reason_code)
        self._trace_reason_counts[key] += 1
        count = self._trace_reason_counts[key]
        # The first affected API must be visible immediately.  Subsequent
        # checkpoints keep growth observable without producing one line per API.
        if count != 1 and count not in {10, 100, 1000, 10000}:
            return
        self.record(
            phase="trace",
            reason_code=reason_code,
            blocking=status == "not_analyzed",
            scope="api",
            message=(
                f"调用链追踪已出现 {status} 结果；"
                f"当前该原因累计影响 {count} 个 API。"
            ),
            failure_count=count,
            current=current,
            total=total,
            samples=[{
                "api_name": str(getattr(result, "api_name", "") or ""),
                "api_signature": str(
                    getattr(result, "api_signature", "") or ""
                ),
                "analysis_status": status,
            }],
        )


__all__ = [
    "STEP5_DIAGNOSTICS_SCHEMA",
    "Step5DiagnosticRecorder",
]

#!/usr/bin/env python3
"""Incremental Step5 diagnostics for long-running analysis.

The final ``summary.json`` remains the conclusion artifact.  This module owns a
small append-only observability ledger so failures are visible when they are
discovered instead of only after every API has been traced and rendered.
"""

from __future__ import annotations

import json
import os
import time
import csv
from collections import Counter, defaultdict
from datetime import datetime, timezone
from itertools import islice
from pathlib import Path

from diagnostic_contract import canonical_reason_code, normalize_diagnostic_payload
from csv_io import open_csv_write
from pipeline_constants import STEP5_PROGRESS_FILE
from progress_logging import emit_progress


STEP5_DIAGNOSTICS_SCHEMA = "java-upgrade-analyzer.step5-diagnostics.v1"
STEP5_PROGRESS_SCHEMA = "java-upgrade-analyzer.step5-progress.v1"
_SAMPLE_LIMIT = 5
_PROGRESS_FLUSH_INTERVAL_SECONDS = 1.0
BYTECODE_UNRESOLVED_EVIDENCE_FILE = "evidence/call_chain/bytecode_unresolved.csv"
BYTECODE_UNRESOLVED_FIELDS = (
    "collector",
    "reason_code",
    "caller_class",
    "caller_method",
    "caller_symbol",
    "caller_qualified_key",
    "instruction_offset",
    "unresolved_owner",
    "unresolved_method",
    "unresolved_signature",
    "unresolved_symbol",
    "instruction_reference",
    "artifact",
    "artifact_entry",
    "source_line",
    "detail",
)


def _split_java_symbol(value):
    symbol = str(value or "").strip()
    if not symbol:
        return "", "", ""
    head, separator, signature_tail = symbol.partition("(")
    signature = "(" + signature_tail if separator else ""
    if "." not in head:
        return "", head, signature
    owner, member = head.rsplit(".", 1)
    return owner, member, signature


def _caller_method(occurrence):
    caller_symbol = str(getattr(occurrence, "caller_symbol", "") or "").strip()
    caller_class = str(getattr(occurrence, "class_name", "") or "").strip()
    head = caller_symbol.split("(", 1)[0]
    if caller_class and head.startswith(caller_class + "."):
        return head[len(caller_class) + 1:]
    return head.rsplit(".", 1)[-1] if head else ""


def _instruction_reference(failure, occurrence):
    target_owner, target_method, target_signature = _split_java_symbol(
        getattr(failure, "api_identity", "")
    )
    caller_class = str(getattr(occurrence, "class_name", "") or "").strip()
    if not caller_class:
        caller_class, _member, _signature = _split_java_symbol(
            getattr(occurrence, "caller_symbol", "")
        )
    offset = getattr(occurrence, "instruction_offset", -1)
    offset_text = str(offset) if isinstance(offset, int) and offset >= 0 else "?"
    caller_method = _caller_method(occurrence) or "?"
    target = ".".join(
        value for value in (target_owner, target_method) if value
    ) or str(getattr(failure, "api_identity", "") or "?")
    return (
        f"{caller_class or '?'}:{caller_method}:{offset_text} -> "
        f"{target}{target_signature}"
    )


def _failure_sample(failure):
    sample = {
        "stage": str(getattr(failure, "stage", "") or ""),
        "artifact": str(getattr(failure, "artifact", "") or ""),
        "class_name": str(getattr(failure, "class_name", "") or ""),
        "api_identity": str(getattr(failure, "api_identity", "") or ""),
        "detail": str(getattr(failure, "detail", "") or "")[:1000],
    }
    occurrences = getattr(failure, "occurrences", ()) or ()
    if occurrences:
        sample_occurrences = (
            occurrences[:_SAMPLE_LIMIT]
            if hasattr(occurrences, "__getitem__")
            else tuple(islice(occurrences, _SAMPLE_LIMIT))
        )
        sample["instruction_evidence"] = [
            _instruction_reference(failure, occurrence)
            for occurrence in sample_occurrences
        ]
    return sample


class Step5DiagnosticRecorder:
    """Write bounded, immediately readable Step5 diagnostic events."""

    def __init__(
        self,
        report_dir,
        *,
        reset=True,
        progress_flush_interval_seconds=_PROGRESS_FLUSH_INTERVAL_SECONDS,
    ):
        self.report_dir = Path(report_dir).resolve()
        self.path = (
            self.report_dir
            / ".runtime"
            / "observability"
            / "step5_diagnostics.jsonl"
        )
        self.progress_path = self.path.with_name(STEP5_PROGRESS_FILE)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if reset:
            self.path.write_text("", encoding="utf-8")
            try:
                (self.report_dir / BYTECODE_UNRESOLVED_EVIDENCE_FILE).unlink(
                    missing_ok=True
                )
            except OSError:
                pass
            try:
                self.progress_path.unlink(missing_ok=True)
            except OSError:
                pass
        self._trace_reason_counts = Counter()
        self._trace_started_at = ""
        self._trace_started_perf = None
        self._last_progress_flush_perf = 0.0
        self._latest_progress = {}
        try:
            interval = float(progress_flush_interval_seconds)
        except (TypeError, ValueError):
            interval = _PROGRESS_FLUSH_INTERVAL_SECONDS
        self._progress_flush_interval_seconds = max(0.0, interval)

    def _write_progress_snapshot(self, payload):
        temporary_path = self.progress_path.with_name(
            f".{self.progress_path.name}.{os.getpid()}.tmp"
        )
        try:
            with temporary_path.open("w", encoding="utf-8", newline="\n") as handle:
                json.dump(payload, handle, ensure_ascii=False, sort_keys=True)
                handle.write("\n")
                handle.flush()
            os.replace(temporary_path, self.progress_path)
            return True
        except (OSError, TypeError, ValueError):
            return False
        finally:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass

    def start_trace(self, total):
        self._trace_started_at = datetime.now(timezone.utc).isoformat()
        self._trace_started_perf = time.perf_counter()
        self._last_progress_flush_perf = 0.0
        self._latest_progress = {}
        return self.record_trace_progress(0, total, force=True)

    def record_trace_progress(self, completed, total, *, force=False, status="running"):
        try:
            completed = int(completed)
            total = int(total)
        except (TypeError, ValueError):
            return {}
        if total < 0 or completed < 0 or completed > total:
            return {}
        previous = dict(self._latest_progress or {})
        if previous:
            previous_total = int(previous.get("total") or 0)
            previous_completed = int(previous.get("completed") or 0)
            if previous_total != total or completed < previous_completed:
                return previous
        if self._trace_started_perf is None:
            self._trace_started_at = datetime.now(timezone.utc).isoformat()
            self._trace_started_perf = time.perf_counter()
            force = True
        now_perf = time.perf_counter()
        elapsed = max(0.0, now_perf - self._trace_started_perf)
        payload = {
            "schema": STEP5_PROGRESS_SCHEMA,
            "step_id": "step5",
            "phase": "trace",
            "status": str(status or "running"),
            "completed": completed,
            "total": total,
            "percentage": round(100.0 * completed / total, 3) if total else 100.0,
            "trace_started_at": self._trace_started_at,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "elapsed_sec": round(elapsed, 3),
        }
        self._latest_progress = payload
        should_flush = (
            force
            or completed == total
            or now_perf - self._last_progress_flush_perf
            >= self._progress_flush_interval_seconds
        )
        if should_flush and self._write_progress_snapshot(payload):
            self._last_progress_flush_perf = now_perf
        return payload

    def finish_trace(self, completed, total):
        return self.record_trace_progress(
            completed,
            total,
            force=True,
            status="completed",
        )

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
        evidence_file="",
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
                "evidence_file": str(evidence_file or ""),
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

    def _write_bytecode_unresolved_evidence(self, failures):
        ordered_failures = sorted(
            (
                (collector, failure)
                for collector, failure in failures
                if getattr(failure, "occurrences", ())
            ),
            key=lambda item: (
                str(item[0] or ""),
                str(getattr(item[1], "api_identity", "") or ""),
                str(getattr(item[1], "artifact", "") or ""),
            ),
        )
        if not ordered_failures:
            return ""
        path = self.report_dir / BYTECODE_UNRESOLVED_EVIDENCE_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = path.with_name(
            f".{path.name}.{os.getpid()}.tmp"
        )
        try:
            with open_csv_write(temporary_path) as handle:
                writer = csv.DictWriter(handle, fieldnames=BYTECODE_UNRESOLVED_FIELDS)
                writer.writeheader()
                # EvidenceFailure already de-duplicates and sorts its immutable
                # occurrence tuple.  Stream rows directly so a 100k-instruction
                # ledger does not create a second object graph during reporting.
                for collector, failure in ordered_failures:
                    target_owner, target_method, target_signature = (
                        _split_java_symbol(
                            getattr(failure, "api_identity", "")
                        )
                    )
                    for occurrence in getattr(
                        failure, "occurrences", ()
                    ) or ():
                        offset = getattr(
                            occurrence, "instruction_offset", -1
                        )
                        writer.writerow({
                            "collector": str(collector or ""),
                            "reason_code": "BYTECODE_CALLER_UNRESOLVED",
                            "caller_class": str(
                                getattr(occurrence, "class_name", "") or ""
                            ),
                            "caller_method": _caller_method(occurrence),
                            "caller_symbol": str(
                                getattr(occurrence, "caller_symbol", "") or ""
                            ),
                            "caller_qualified_key": str(
                                getattr(
                                    occurrence, "caller_qualified_key", ""
                                ) or ""
                            ),
                            "instruction_offset": (
                                offset
                                if isinstance(offset, int) and offset >= 0
                                else ""
                            ),
                            "unresolved_owner": target_owner,
                            "unresolved_method": target_method,
                            "unresolved_signature": target_signature,
                            "unresolved_symbol": str(
                                getattr(failure, "api_identity", "") or ""
                            ),
                            "instruction_reference": _instruction_reference(
                                failure, occurrence
                            ),
                            "artifact": str(
                                getattr(occurrence, "artifact", "") or ""
                            ),
                            "artifact_entry": str(
                                getattr(occurrence, "artifact_entry", "") or ""
                            ),
                            "source_line": getattr(
                                occurrence, "line", 0
                            ) or "",
                            "detail": str(
                                getattr(occurrence, "detail", "") or ""
                            ),
                        })
            os.replace(temporary_path, path)
        except (OSError, TypeError, ValueError):
            return ""
        finally:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
        return BYTECODE_UNRESOLVED_EVIDENCE_FILE

    def record_failure_records(
        self, phase, failure_records, *, reason_codes=None
    ):
        accepted_codes = {
            canonical_reason_code(value)
            for value in (reason_codes or ())
            if str(value or "").strip()
        }
        grouped = defaultdict(list)
        normalized_records = []
        for collector, failure in failure_records or ():
            reason_code = canonical_reason_code(
                getattr(failure, "reason_code", "")
            )
            if accepted_codes and reason_code not in accepted_codes:
                continue
            normalized_records.append((str(collector or "unknown"), failure))
            key = (
                reason_code,
                bool(getattr(failure, "blocking", False)),
                str(getattr(failure, "scope", "") or "global"),
            )
            grouped[key].append((str(collector or "unknown"), failure))

        unresolved_evidence_file = self._write_bytecode_unresolved_evidence([
            (collector, failure)
            for collector, failure in normalized_records
            if canonical_reason_code(getattr(failure, "reason_code", ""))
            == "BYTECODE_CALLER_UNRESOLVED"
        ])

        events = []
        for (reason_code, blocking, scope), failures in sorted(grouped.items()):
            evidence_file = (
                unresolved_evidence_file
                if reason_code == "BYTECODE_CALLER_UNRESOLVED"
                else ""
            )
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
                evidence_file=evidence_file,
                samples=[
                    _failure_sample(failure)
                    for _collector, failure in failures[:_SAMPLE_LIMIT]
                ],
            ))
        return events

    def record_collector_failures(self, phase, collector_batches):
        failure_records = []
        for batch in collector_batches or ():
            collector = str(getattr(batch, "collector", "") or "unknown")
            for failure in getattr(batch, "failures", ()) or ():
                failure_records.append((collector, failure))
        return self.record_failure_records(phase, failure_records)

    def record_trace_result(self, result, current, total):
        self.record_trace_progress(current, total)
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
    "STEP5_PROGRESS_SCHEMA",
    "BYTECODE_UNRESOLVED_EVIDENCE_FILE",
    "Step5DiagnosticRecorder",
]

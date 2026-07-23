#!/usr/bin/env python3
"""Incremental Step1 progress events and phase timing records."""

from __future__ import annotations

import csv
import json
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from csv_io import open_csv_write
from pipeline_constants import (
    EVIDENCE_DEPENDENCIES_DIRNAME,
    EVIDENCE_DIRNAME,
    RUNTIME_CACHE_DIRNAME,
    RUNTIME_DIRNAME,
    RUNTIME_OBSERVABILITY_DIRNAME,
)
from progress_logging import emit_progress


TIMING_FIELDS = (
    "side", "phase", "item", "started_at", "ended_at", "elapsed_sec",
    "peak_rss_mb", "archive_bytes", "nested_entries", "cache_hits",
    "cache_misses", "status", "command", "message",
)


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def peak_rss_mb():
    """Return this process's high-water RSS in MiB on supported platforms."""
    try:
        import resource

        raw = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss or 0.0)
    except (ImportError, OSError, ValueError):
        return 0.0
    divisor = 1024.0 * 1024.0 if sys.platform == "darwin" else 1024.0
    return raw / divisor


@dataclass(frozen=True)
class PhaseToken:
    row_index: int
    side: str
    phase: str
    item: str
    command: str
    started_at: str
    started_perf: float


class Step1Observer:
    """Write append-only progress plus completed phase timings.

    ``dep_changes.csv`` remains the authoritative completed result. These two
    files are diagnostics and are safe to inspect while Step1 is still running.
    """

    def __init__(self, output_path):
        output_path = Path(output_path).expanduser().resolve()
        output_dir = output_path.parent
        if (
            output_dir.name == EVIDENCE_DEPENDENCIES_DIRNAME
            and output_dir.parent.name == EVIDENCE_DIRNAME
        ):
            report_dir = output_dir.parent.parent
        else:
            report_dir = output_dir
        observability_dir = (
            report_dir / RUNTIME_DIRNAME / RUNTIME_OBSERVABILITY_DIRNAME
        )
        self.report_dir = report_dir
        self.cache_dir = report_dir / RUNTIME_DIRNAME / RUNTIME_CACHE_DIRNAME
        self._counters = {
            "archive_bytes": 0,
            "nested_entries": 0,
            "cache_hits": 0,
            "cache_misses": 0,
        }
        self._timing_rows = []
        self._timing_lock = threading.RLock()
        observability_dir.mkdir(parents=True, exist_ok=True)
        self.progress_path = observability_dir / "step1_progress.jsonl"
        self.timing_path = observability_dir / "step1_timing.csv"
        for legacy_path in (
            output_dir / "step1_progress.jsonl",
            output_dir / "step1_timing.csv",
        ):
            if legacy_path.exists():
                legacy_path.unlink()
        self.progress_path.write_text("", encoding="utf-8")
        self._flush_timing()

    def _flush_timing(self):
        with self._timing_lock:
            rows = list(self._timing_rows)
            with open_csv_write(self.timing_path) as handle:
                writer = csv.DictWriter(handle, fieldnames=TIMING_FIELDS)
                writer.writeheader()
                writer.writerows(rows)

    def _timing_row(
        self,
        token,
        *,
        status,
        message,
        ended_at="",
        elapsed_sec="",
    ):
        return {
            "side": token.side,
            "phase": token.phase,
            "item": token.item,
            "started_at": token.started_at,
            "ended_at": ended_at,
            "elapsed_sec": elapsed_sec,
            "peak_rss_mb": f"{peak_rss_mb():.3f}",
            "archive_bytes": str(self._counters["archive_bytes"]),
            "nested_entries": str(self._counters["nested_entries"]),
            "cache_hits": str(self._counters["cache_hits"]),
            "cache_misses": str(self._counters["cache_misses"]),
            "status": str(status or ""),
            "command": token.command,
            "message": str(message or ""),
        }

    def increment_counter(self, name, amount=1):
        if name not in self._counters:
            raise KeyError(f"unsupported Step1 counter: {name}")
        self._counters[name] += int(amount or 0)

    def event(
        self,
        phase,
        status,
        message,
        *,
        side="",
        item="",
        command="",
        elapsed_sec=None,
        details=None,
    ):
        payload = {
            "timestamp": _utc_now(),
            "step": "step1",
            "side": str(side or ""),
            "phase": str(phase or ""),
            "status": str(status or ""),
            "elapsed_sec": round(float(elapsed_sec), 3) if elapsed_sec is not None else None,
            "item": str(item or ""),
            "command": str(command or ""),
            "message": str(message or ""),
            "details": dict(details or {}),
        }
        with self.progress_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
        emit_progress(
            "step1", payload["phase"], payload["message"],
            elapsed=payload["elapsed_sec"], item=payload["side"] or payload["item"] or None,
        )
        return payload

    def start_phase(self, phase, *, side="", item="", command="", message=""):
        with self._timing_lock:
            token = PhaseToken(
                row_index=len(self._timing_rows),
                side=str(side or ""), phase=str(phase or ""), item=str(item or ""),
                command=str(command or ""), started_at=_utc_now(),
                started_perf=time.perf_counter(),
            )
            start_message = message or f"开始 {token.phase}"
            self._timing_rows.append(
                self._timing_row(
                    token,
                    status="running",
                    message=start_message,
                )
            )
            self._flush_timing()
        self.event(
            token.phase, "running", start_message,
            side=token.side, item=token.item, command=token.command, elapsed_sec=0,
        )
        return token

    def finish_phase(self, token, *, status, message=""):
        elapsed = time.perf_counter() - token.started_perf
        ended_at = _utc_now()
        final_message = message or f"{token.phase} {status}"
        self.event(
            token.phase, status, final_message, side=token.side, item=token.item,
            command=token.command, elapsed_sec=elapsed,
        )
        with self._timing_lock:
            completed_row = self._timing_row(
                token,
                status=status,
                message=final_message,
                ended_at=ended_at,
                elapsed_sec=f"{elapsed:.3f}",
            )
            if 0 <= token.row_index < len(self._timing_rows):
                self._timing_rows[token.row_index] = completed_row
            else:
                self._timing_rows.append(completed_row)
            self._flush_timing()
        return elapsed

    @contextmanager
    def phase(self, phase, *, side="", item="", command="", start_message="", complete_message=""):
        token = self.start_phase(
            phase, side=side, item=item, command=command, message=start_message,
        )
        try:
            yield token
        except BaseException as exc:
            self.finish_phase(
                token,
                status="failed",
                message=f"{phase} 失败：{exc.__class__.__name__}: {exc}",
            )
            raise
        else:
            self.finish_phase(
                token, status="completed", message=complete_message or f"{phase} 完成",
            )


__all__ = ["PhaseToken", "Step1Observer", "TIMING_FIELDS", "peak_rss_mb"]

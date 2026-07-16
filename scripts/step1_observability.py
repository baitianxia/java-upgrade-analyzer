#!/usr/bin/env python3
"""Incremental Step1 progress events and phase timing records."""

from __future__ import annotations

import csv
import json
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from pipeline_constants import (
    EVIDENCE_DEPENDENCIES_DIRNAME,
    EVIDENCE_DIRNAME,
    RUNTIME_DIRNAME,
    RUNTIME_OBSERVABILITY_DIRNAME,
)
from progress_logging import emit_progress


TIMING_FIELDS = (
    "side", "phase", "item", "started_at", "ended_at", "elapsed_sec",
    "status", "command", "message",
)


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass(frozen=True)
class PhaseToken:
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
        with self.timing_path.open("w", encoding="utf-8", newline="") as handle:
            csv.DictWriter(handle, fieldnames=TIMING_FIELDS).writeheader()

    def event(self, phase, status, message, *, side="", item="", command="", elapsed_sec=None):
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
        }
        with self.progress_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
        emit_progress(
            "step1", payload["phase"], payload["message"],
            elapsed=payload["elapsed_sec"], item=payload["side"] or payload["item"] or None,
        )
        return payload

    def start_phase(self, phase, *, side="", item="", command="", message=""):
        token = PhaseToken(
            side=str(side or ""), phase=str(phase or ""), item=str(item or ""),
            command=str(command or ""), started_at=_utc_now(), started_perf=time.perf_counter(),
        )
        self.event(
            token.phase, "running", message or f"开始 {token.phase}",
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
        with self.timing_path.open("a", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=TIMING_FIELDS)
            writer.writerow({
                "side": token.side,
                "phase": token.phase,
                "item": token.item,
                "started_at": token.started_at,
                "ended_at": ended_at,
                "elapsed_sec": f"{elapsed:.3f}",
                "status": str(status or ""),
                "command": token.command,
                "message": final_message,
            })
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


__all__ = ["PhaseToken", "Step1Observer", "TIMING_FIELDS"]

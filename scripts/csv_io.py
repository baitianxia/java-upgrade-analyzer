#!/usr/bin/env python3
"""Shared UTF-8 BOM boundary for every CSV produced or consumed by the tool."""

from __future__ import annotations

import codecs
import os
import shutil
from pathlib import Path

from path_runtime import named_temporary_file

CSV_ENCODING = "utf-8-sig"
UTF8_BOM = codecs.BOM_UTF8


def open_csv_read(path):
    """Open a BOM or historical plain UTF-8 CSV for reading."""
    return Path(path).open("r", encoding=CSV_ENCODING, newline="")


def open_csv_write(path):
    """Create or replace a CSV that emits one leading UTF-8 BOM on first write."""
    return Path(path).open("w", encoding=CSV_ENCODING, newline="")


def _ensure_leading_bom(path):
    """Upgrade an existing non-empty plain UTF-8 file without loading it in memory."""
    target = Path(path)
    if not target.exists() or target.stat().st_size == 0:
        return
    with target.open("rb") as source:
        if source.read(len(UTF8_BOM)) == UTF8_BOM:
            return

    temporary_path = None
    try:
        with named_temporary_file(
            mode="wb",
            prefix=".jua-bom-",
            suffix=".tmp",
            dir=target.parent,
            delete=False,
        ) as output:
            temporary_path = Path(output.name)
            output.write(UTF8_BOM)
            with target.open("rb") as source:
                shutil.copyfileobj(source, output, length=1024 * 1024)
        shutil.copymode(target, temporary_path)
        os.replace(temporary_path, target)
        temporary_path = None
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def open_csv_append(path):
    """Append CSV rows while guaranteeing exactly one BOM at the beginning."""
    target = Path(path)
    if not target.exists() or target.stat().st_size == 0:
        return target.open("a", encoding=CSV_ENCODING, newline="")
    _ensure_leading_bom(target)
    # utf-8-sig creates a BOM for each new encoder. Existing files therefore
    # append as plain UTF-8 after the leading BOM has been verified.
    return target.open("a", encoding="utf-8", newline="")

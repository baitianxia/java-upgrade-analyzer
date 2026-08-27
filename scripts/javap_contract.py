#!/usr/bin/env python3
"""Stable locale and encoding contract shared by every javap invocation."""

from __future__ import annotations


JAVAP_STABLE_JVM_OPTIONS = (
    "-J-Dfile.encoding=UTF-8",
    "-J-Dsun.stdout.encoding=UTF-8",
    "-J-Dsun.stderr.encoding=UTF-8",
    "-J-Dstdout.encoding=UTF-8",
    "-J-Dstderr.encoding=UTF-8",
    "-J-Duser.language=en",
    "-J-Duser.country=US",
)


def javap_command(javap: str, *arguments: str) -> list[str]:
    """Build a javap command under the analyzer's stable text contract."""
    return [javap, *JAVAP_STABLE_JVM_OPTIONS, *arguments]


__all__ = ["JAVAP_STABLE_JVM_OPTIONS", "javap_command"]

"""Install child-process call evidence only when the coverage gate requests it."""

from __future__ import annotations

import json
import os
from pathlib import Path


def _record_installation_failure(error: BaseException) -> None:
    directory = os.environ.get("JUA_WHITEBOX_CALL_OUTPUT_DIRECTORY", "")
    if not directory:
        return
    try:
        target = Path(directory)
        target.mkdir(parents=True, exist_ok=True)
        (target / f"profile-error-{os.getpid()}.json").write_text(
            json.dumps({
                "schema": "java-upgrade-analyzer.whitebox-profile-error.v1",
                "process_id": os.getpid(),
                "error": f"{type(error).__name__}: {error}",
            }, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except BaseException:
        # This hook must not corrupt the product subprocess being measured.
        # The missing process payload remains visible to the completeness gate.
        pass


try:
    from whitebox_call_coverage import install_process_profiler_from_environment

    install_process_profiler_from_environment()
except BaseException as error:
    _record_installation_failure(error)

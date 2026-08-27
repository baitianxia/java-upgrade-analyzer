#!/usr/bin/env python3
"""Load one temporary production mutant and run its owning regression test."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys
import unittest


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", required=True)
    parser.add_argument("--mutant", required=True)
    parser.add_argument("--test", required=True)
    args = parser.parse_args(argv)
    scripts = Path(__file__).resolve().parent
    root = scripts.parent
    sys.path.insert(0, str(scripts))
    sys.path.insert(0, str(root))
    try:
        spec = importlib.util.spec_from_file_location(args.module, args.mutant)
        if spec is None or spec.loader is None:
            raise ImportError("mutant module spec or loader is unavailable")
        module = importlib.util.module_from_spec(spec)
        sys.modules[args.module] = module
        spec.loader.exec_module(module)
        loader = unittest.defaultTestLoader
        loader.errors.clear()
        suite = loader.loadTestsFromName(args.test)
        if loader.errors or suite.countTestCases() == 0:
            raise ImportError(
                "; ".join(loader.errors) or "owning test selector resolved to zero tests"
            )
    except Exception as error:  # noqa: BLE001 - worker load failures are evidence
        print(json.dumps({
            "status": "worker_load_failed",
            "detail": f"{type(error).__name__}: {error}",
        }, ensure_ascii=False), file=sys.stderr)
        return 4
    result = unittest.TextTestRunner(verbosity=0).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())

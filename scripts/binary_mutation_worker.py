#!/usr/bin/env python3
"""Load one temporary production mutant and run its owning regression test."""

from __future__ import annotations

import argparse
import importlib.util
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
    spec = importlib.util.spec_from_file_location(args.module, args.mutant)
    if spec is None or spec.loader is None:
        return 4
    module = importlib.util.module_from_spec(spec)
    sys.modules[args.module] = module
    spec.loader.exec_module(module)
    suite = unittest.defaultTestLoader.loadTestsFromName(args.test)
    result = unittest.TextTestRunner(verbosity=0).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())

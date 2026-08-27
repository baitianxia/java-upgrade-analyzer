#!/usr/bin/env python3
"""Run mutation tests while distinguishing loader failures from killed mutants."""

from __future__ import annotations

import json
import os
import sys
import unittest


def main(argv=None):
    test_ids = list(sys.argv[1:] if argv is None else argv)
    sys.path.insert(0, os.getcwd())
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(test_ids)
    test_count = suite.countTestCases()
    if loader.errors or test_count <= 0:
        print(json.dumps({
            "schema": "java-upgrade-analyzer.production-mutation-worker.v1",
            "status": "infrastructure_failed",
            "test_count": test_count,
            "loader_errors": list(loader.errors),
        }, ensure_ascii=False))
        return 4
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())

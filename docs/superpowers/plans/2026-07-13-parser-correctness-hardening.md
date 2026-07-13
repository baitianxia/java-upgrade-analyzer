# Parser Correctness Hardening Implementation Plan

1. Lock current behavior with the existing suite and add failing reproductions for the confirmed defects.
2. Restore the constant-pool candidate filter and separate shallow/full immutable cache capabilities.
3. Correct switch alignment and parse BootstrapMethods targets, with `javap` fallback on incomplete classfiles.
4. Add provenance-based nested application-module ownership and a multi-module root discovery regression.
5. Parse topology headers directly and preserve fail-closed timeout/coverage behavior.
6. Preserve worker exception diagnostics and prevent failed results from entering success caches.
7. Add safe worktree registration/removal during Step 5 cleanup and failed materialization.
8. Harden Java/XML/YAML/Maven parsing without changing existing accepted inputs.
9. Isolate and bound tree-sitter preflight installation while preserving explicit degradation approval.
10. Run focused, full, compiled-fixture, and real-project regressions; document results and remaining limits.

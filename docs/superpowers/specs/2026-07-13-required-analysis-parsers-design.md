# Required Analysis Parsers Design

## Goal

Make JApiCmp and tree-sitter mandatory prerequisites for Java upgrade analysis: the Skill must not emit a degraded Step4 or Step5 conclusion when either required tool is unavailable.

## Decisions

- Step4 keeps its automatic JApiCmp installation attempt. If an upgraded dependency requires binary comparison and JApiCmp remains unavailable, Step4 writes its preflight evidence, emits a hard-stop checkpoint, and exits. `allow_degraded` cannot override this decision.
- Step5 keeps its automatic tree-sitter installation attempt. If Java source is in scope and tree-sitter remains unavailable, Step5 writes its preflight evidence, emits a hard-stop checkpoint, and exits. `allow_degraded` cannot override this decision.
- Checkpoint response schemas permit only installation confirmation and the concrete JApiCmp path where applicable. They never advertise or accept `allow_degraded` as a way to resume either parser prerequisite.
- Regex analysis remains an internal development fallback only. The orchestrated Skill path may not reach it for Java sources.

## Error Handling

An installation/load failure remains visible in `japicmp_preflight.json` or `tree_sitter_preflight.json`, plus the checkpoint payload. Restarting requires the missing tool to be installed and the relevant confirmation field supplied. This is intentionally fail-closed: no Step5/Step6 conclusion follows a failed prerequisite.

## Verification

Regression tests must prove that an `allow_degraded=true` response is rejected for both parser checkpoints; that the interaction schema no longer includes it; and that the normal installed-tool path remains unchanged.

# Step5 Evidence Model Design

## Objective

Refactor Step5 so evidence collection, module ownership, reachability construction,
and user-facing conclusions are separate responsibilities. Scanners must report
facts and failures; only one policy component may decide `reachable`, `uncertain`,
`not_analyzed`, `not_found_in_static_analysis`, or `not_impacted`.

The refactor must preserve current report schemas and keep the existing real-project
guards and full regression suite passing throughout the migration.

## Scope

This design covers Step5 final-artifact analysis and its interaction with the
existing source graph. It includes physical bytecode edges, artifact/module
ownership, candidate paths, analysis failures, decision policy, and compatibility
with `TraceResult` and current CSV/JSON outputs.

It does not redesign Step1-Step4, replace the source parser, or introduce a new
graph library.

## Architecture

### Physical Evidence

Create immutable evidence records for facts observed in the current final artifact:

- `PhysicalCallEdge`: caller, callee, descriptors, opcode, instruction offset,
  artifact SHA, artifact entry, class entry, parser, and evidence completeness.
- `EvidenceFailure`: stage, reason code, affected artifact/class/API, and whether
  the failure makes absence conclusions unsafe.

The existing analyzer edge ledger remains the persisted representation. Conversion
between typed records and ledger rows is explicit and tested.

### Module Ownership

Create a single ownership classifier with these scopes:

- `BUSINESS_CLASSES`: classes packaged directly under the executable artifact's
  application-classes location, represented today by `coord == "__business__"`.
- `INTERNAL_MODULE`: application-owned nested modules.
- `EXTERNAL_DEPENDENCY`: other runtime dependencies.
- `UNKNOWN`: incomplete or conflicting provenance.

`application_owned` may select `INTERNAL_MODULE`; it must never imply
`BUSINESS_CLASSES` or business reachability.

### Reachability Paths

Create typed path records that contain ordered physical/source edges, an entry
scope, target API identity, confidence, stop reason, and completeness. Path building
may return:

- a complete business path;
- an internal/runtime-only candidate path;
- a truncated path;
- an ambiguous-signature candidate path.

Path construction does not assign an API analysis status.

### Decision Policy

Introduce one pure decision function that consumes target identity, candidate
paths, evidence failures, and preservation facts, and returns an immutable
`AnalysisDecision`.

Initial policy:

- Complete, non-ambiguous path from `BUSINESS_CLASSES` or a proven runtime framework
  activation to the target: `reachable`.
- Complete proof that the changed API remains present and compatible:
  `not_impacted`.
- Physical/internal references without a proven business entry: `uncertain`.
- Signature ambiguity that can change overload identity: `uncertain` with an input
  requirement.
- Parse failure, timeout, incomplete catalog, depth truncation, or missing required
  metadata: `not_analyzed` unless stronger positive evidence independently proves
  reachability.
- Complete scan with no matching edge and no evidence failure:
  `not_found_in_static_analysis`.

Only this component may create new final status values during the migrated path.

## Compatibility Strategy

Migration is incremental:

1. Add typed evidence, ownership, path, and decision modules without changing
   production behavior.
2. Adapt packaged-bytecode analysis to produce typed facts and derive the existing
   `TraceResult` through a compatibility adapter.
3. Move source/direct/framework outcomes through the same decision policy.
4. Remove migrated direct assignments to `TraceResult.analysis_status`.

Existing fields remain available:

- `call_paths`
- `evidence_paths`
- `path_details`
- `reason_code`
- `analysis_status`
- `is_reachable`

The adapter is responsible for rendering them from typed decisions and paths.

## Invariants

- Every reachable path has a concrete business or proven framework entry.
- Every rendered edge maps to physical/source evidence with provenance.
- Internal-module ownership alone never proves reachability.
- An ambiguous edge never promotes a path to reachable.
- Absence is conclusive only when scan coverage is complete.
- Depth and performance truncation are represented as evidence failures.
- Query indexes are written from the same expanded graph used for decisions.
- Evidence collection order and worker scheduling do not change conclusions.

## Error Handling

Parser, archive, descriptor, and provenance failures become `EvidenceFailure`
records. Broad exception boundaries may protect batch progress, but every caught
failure must identify its stage and affected scope. A failure that prevents a
complete negative proof blocks `not_found_in_static_analysis`.

## Testing

Each migration step uses TDD and includes:

- pure policy truth-table tests;
- ownership classification tests;
- path completeness and ambiguity tests;
- adapter parity tests against current `TraceResult` output;
- mixed-evidence tests where exact and ambiguous edges coexist;
- depth, timeout, parser failure, and incomplete-catalog tests;
- deterministic parallel-scan tests;
- the full unit suite;
- `gs-multi-module` final-artifact guard;
- a second real project selected for a topology not already covered.

Third-party `javap` edge truth remains authoritative for physical call instructions.

## Delivery Phases

### Phase 1: Model and Packaged-Bytecode Policy

Add the typed model, pure decision policy, and compatibility adapter. Migrate
`_build_packaged_dependency_hit_result` first because it currently combines all
four responsibilities and caused the recent internal-module false positive.

### Phase 2: Failure and Negative Conclusions

Normalize scan/parse/depth/performance failures and route packaged-bytecode
`uncertain`, `not_analyzed`, and `not_found_in_static_analysis` through policy.

### Phase 3: Source and Framework Paths

Convert direct source usage, source/artifact conflicts, and framework activation
paths to typed paths and the shared decision policy.

### Phase 4: Remove Legacy Decision Writes

Inventory and eliminate remaining migrated direct assignments to
`TraceResult.analysis_status`. Keep explicit compatibility handling only at the
output boundary.

## Acceptance Criteria

- Existing report schemas remain readable by Step6.
- All existing tests pass at every phase.
- New policy and adapter tests cover every decision state.
- `gs-multi-module` retains its complete two-edge business path and all gates pass.
- No scanner or path builder in the migrated packaged-bytecode flow directly sets
  a final analysis status.
- Independent review finds no P1/P2 correctness blocker before each phase commit.


# Real Project Testing V3: Topology and Edge Truth

Date: 2026-07-11

## Problem

V2 made API coverage, final conclusions, independent API oracles, and
performance visible. It still treated a project and an API as the effective
test unit. That allowed a project to pass direct business-to-dependency calls
without exercising dependency-internal bridges, same-coordinate calls, or
source/bytecode conflict decisions.

The `gs-multi-module` finding demonstrates the gap. A complete candidate chain
can be present while three same-coordinate filters remove the packaged
bytecode edge needed to confirm it. Project size and 100% API accounting do not
prove that all relevant call-chain topologies were exercised.

## Decision

The V3 test unit is:

```text
final artifact + API identity + topology + edge truth + conclusion + performance
```

V3 retains every V2 gate and adds topology coverage and exhaustive edge
verification. A discovery or convergence case cannot pass merely because all
selected APIs have a conclusion. It must cover its declared required topology
classes and reconcile every authoritative bytecode edge involved in those
topologies.

## Non-Negotiable Evidence Boundary

Deterministic runtime claims use only a SHA-256-verified
`current_final_artifact`.

- Business classes come from `BOOT-INF/classes`, `WEB-INF/classes`, or valid
  root class entries in the final artifact.
- Runtime dependencies come from the final artifact's packaged dependency
  entries.
- `target/classes`, IDE output, source compilation directories, and stale jars
  are never runtime truth and cannot be degraded into a reachable conclusion.
- A missing, unreadable, or hash-mismatched final artifact fails closed.
- Source evidence remains useful for explanation and candidate discovery, but
  it cannot override contradictory final-artifact bytecode.

Every authoritative edge records artifact path, artifact SHA-256, entry path,
caller identity, callee identity, JVM descriptor, opcode family, and authority
procedure/version.

## Canonical Edge Identity

An executable edge uses this canonical identity:

```text
artifact_sha256 |
caller_owner | caller_member | caller_descriptor |
callee_owner | callee_member | callee_descriptor |
opcode_family
```

Constructors retain `<init>`. Interface and virtual calls retain their opcode
family. Source names, erased simple names, and display signatures are metadata,
not identity fields.

The analyzer edge ledger and third-party edge oracle must independently
produce this schema. They must not share parsed class structures, indexes, or
matching results.

## Required Topology Taxonomy

Each topology has a stable ID. Discovery selection and release reports use the
ID rather than prose labels.

| ID | Required shape |
| --- | --- |
| `business_direct` | final-artifact business class directly invokes target API |
| `same_jar_bridge` | another method in the target runtime jar invokes target API |
| `cross_jar_bridge` | a different runtime jar invokes target API |
| `business_to_same_jar_bridge` | business entry reaches a same-jar caller that invokes target API |
| `business_to_cross_jar_bridge` | business entry reaches a different-jar caller that invokes target API |
| `same_coord_multimodule` | packaged modules sharing a coordinate boundary require internal edges |
| `overloaded_method` | exact owner/member/descriptor selects one overload |
| `constructor` | exact constructor descriptor is invoked |
| `interface_dispatch` | `invokeinterface` reaches an interface method |
| `virtual_dispatch` | `invokevirtual` plus hierarchy evidence resolves runtime target family |
| `static_dispatch` | `invokestatic` reaches a static method |
| `field_access` | executable get/put instruction references a changed field |
| `invokedynamic` | bootstrap evidence is required for a dynamic call edge |
| `reflection` | data-flow or executable evidence identifies reflective target |
| `spi` | final-artifact registration and provider evidence form the edge |
| `framework_proxy` | framework registration and proxy contract form the boundary |
| `source_bytecode_agree` | source and final bytecode describe the same executable edge |
| `source_bytecode_true_conflict` | source and verified final artifact genuinely disagree |

Each case declares `required_topologies`. The runner derives
`observed_topologies` from authoritative evidence and analyzer output. Missing
required topology IDs emit blocking `topology_coverage_gap`.

Project selection must be driven by uncovered topology IDs. A large project
that adds no new topology coverage does not consume discovery budget.

## Same-Coordinate Contract

Same-coordinate filtering is replaced by instruction-aware handling:

- A class or method declaration is never a call edge.
- A real `invoke*` instruction inside the target jar is retained as an
  authoritative internal edge.
- An internal edge alone does not prove business reachability.
- The internal edge becomes reachable only when reverse traversal reaches a
  final-artifact business class or another independently valid runtime entry.
- Self-recursive calls are retained but deduplicated by canonical edge identity.
- Scanning the target jar must not automatically classify every internal edge
  as impact; it contributes bridge evidence only.

`gs-multi-module` becomes the first `business_to_same_jar_bridge` and
`same_coord_multimodule` guard. Its minimum chain contract is:

```text
DemoApplication.home
  -> MyService.message
  -> ServiceProperties.getMessage()
```

The expected conclusion is `reachable`. `SOURCE_BYTECODE_EDGE_CONFLICT` is
invalid when the authoritative edge ledger contains both executable edges and
the final artifact matches the analyzed source revision.

## Exhaustive Edge Oracle

For every selected API:

1. Locate every final-artifact bytecode instruction whose exact callee identity
   matches the API.
2. Record all direct callers, including callers from the same coordinate.
3. Recursively enumerate authoritative runtime caller edges needed to connect
   those callers to business classes or runtime boundaries.
4. Compare the analyzer ledger against the oracle ledger without sampling.
5. Classify each canonical edge as `correct`, `missing`, `extra`,
   `identity_mismatch`, `provenance_invalid`, or `oracle_conflict`.

Missing and identity-mismatched edges are P0 for P0/P1 APIs. Extra executable
edges are P0 when they create a false reachable conclusion and P1 otherwise.
Invalid provenance and oracle conflict block the case.

API-level correctness is derived only after edge reconciliation. A matching
final conclusion cannot hide missing or fabricated intermediate edges.

## Source and Bytecode Conflict Rules

`SOURCE_BYTECODE_EDGE_CONFLICT` is allowed only when all conditions hold:

- source revision provenance is known;
- final artifact hash is valid;
- source and bytecode canonical edge identities genuinely differ;
- neither difference is explained by compiler lowering, bridge methods,
  synthetic methods, varargs erasure, or owner normalization;
- the conflict ledger names both edges and the normalization procedure.

If bytecode proves the executable edge and source provides only a less precise
candidate, bytecode wins and no conflict is emitted. If source describes an
edge absent from a complete final artifact, the result remains non-reachable
unless another runtime authority proves it.

## Seven Independent Gates

V3 cases pass all seven gates independently:

1. `asset`: fixed Git revision, valid final artifact, matching SHA-256.
2. `api_coverage`: complete selected API accounting.
3. `topology_coverage`: all required topology IDs observed and verified.
4. `edge_truth`: exhaustive analyzer/oracle edge reconciliation.
5. `conclusion`: no unsupported `uncertain`, `not_analyzed`, or false final
   conclusion.
6. `performance`: absolute and normalized budgets pass without reducing scope.
7. `fixture_debt`: every P0/P1 finding is fixed, planned, or time-bounded
   waived.

Any blocking signal makes runner status `failed`. Ground truth that is not yet
available produces `observed` only when no other gate fails. No aggregate score
or majority vote can override a failed gate.

## Performance Contract

Record and gate:

- final artifact bytes and business/runtime class counts;
- authoritative oracle edge count;
- analyzer edge count;
- bytecode parse time and classes per second;
- edge reconciliation time and edges per second;
- Step5 elapsed time per 1,000 APIs and per 100,000 authoritative edges;
- candidate classes, `javap` fallbacks, cache hits, and duplicate scans;
- peak candidate-pair counts and per-API counts.

The scanner must exclude a target jar from direct consumer classification while
still parsing its internal executable edges exactly once. Optimization may
reuse immutable artifact-hash caches, but cannot skip topology classes or
oracle edges.

## Test Layers

### L0: Parser Contracts

Minimal class files verify owner/member/descriptor/opcode extraction,
constructors, interfaces, bridge methods, synthetic methods, and malformed
artifacts.

### L1: Topology Fixtures

Small reproducible fat jars cover every topology ID with positive and negative
contracts. Each fixture includes an independently generated edge manifest.

### L2: Real Project Discovery

Fixed Git projects provide ecosystem combinations and performance scale. Their
required topology set is measured before conclusions are accepted. New failure
classes are reduced into L0/L1 fixtures.

### L3: Rotation

When a project adds no new topology IDs or findings, discovery rotates to a
project selected for remaining coverage gaps. Converged projects retain only
guard cases.

## Outputs

Each case writes:

- `topology_coverage.json` and `topology_coverage.csv`;
- `oracle_edges.csv`;
- `analyzer_edges.csv`;
- `edge_reconciliation.csv`;
- `api_oracle.csv`;
- `performance_envelope.json`;
- structured quality signals containing topology IDs and edge samples.

Every row links to final-artifact provenance. Human reports summarize these
files but never replace them.

## Acceptance Criteria

V3 is accepted when:

- `gs-multi-module` is `reachable` with same-jar edges preserved;
- declarations alone do not create edges or reachability;
- no deterministic conclusion uses `target/classes`;
- discovery cases fail on missing required topology IDs;
- every selected API and every involved authoritative edge is reconciled;
- source/bytecode conflicts satisfy the strict conflict contract;
- performance budgets are enforced on unchanged scope;
- focused tests and the full repository suite pass;
- P0/P1 findings are represented in fixture-debt output.

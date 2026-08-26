# Pipeline Performance Optimization Design

## Goal

Reduce Step1, Step4, and Step5 wall time and peak memory without changing the
analyzed API population, physical evidence edges, framework semantics, failure
signals, or final conclusions.

## Non-Negotiable Correctness Contract

- Performance work must not reduce the number of archives, classes, APIs,
  physical instructions, framework records, or Oracle checks examined.
- Before and after outputs must have identical canonical API identities,
  conclusions, reason codes, analyzer edge ledgers, and independent Oracle
  reconciliation results. Ordering-only differences are allowed only where the
  output contract does not define order.
- Cache entries are reusable only when every conclusion-relevant input is bound
  by content identity: artifact SHA-256, analyzer/cache schema version, JDK
  target, tool SHA-256, and relevant options.
- Missing, corrupt, stale, or incompatible cache entries cause a complete scan.
  Cache failure must never become `not_found_in_static_analysis` or silently
  remove evidence.
- Concurrency is bounded by an explicit worker count. It may reduce wall time,
  but must not change deterministic merge order or error propagation.
- Independent Oracles do not consume analyzer conclusions or analyzer-produced
  parsed edges. They may reuse immutable input artifacts, but not derived truth.

## Observability First

Step1 and Step4 currently record phase elapsed time but do not record peak RSS.
Add process-level peak RSS, bytes read/written, archive-entry counts, cache
hits/misses, and external-process invocation counts. Step5 keeps its existing
metrics and adds cache-size and retained-graph metrics where needed.

Performance acceptance uses repeated measurements on pinned artifacts. A change
is accepted only when correctness parity passes first, then the median warm and
cold timings show a material improvement without a peak-memory regression.

## Step1 Design

The current packaged-archive path reads each nested JAR into a complete `bytes`
object, hashes it, and opens another in-memory ZIP view. Replace this with a
bounded spool abstraction that streams the outer ZIP entry once, computes its
SHA-256 while copying, and exposes a seekable source to `zipfile.ZipFile`.
Small entries may remain in memory under a fixed threshold; large entries spill
to the report runtime directory or system temporary directory and are removed
after inspection.

Persist the packaged dependency inventory by final-artifact SHA-256 and cache
schema version. The cached record contains the exact entry name, content hash,
coordinate evidence, resolution status, and read errors. Cache hits reproduce
the same normalized records; malformed cache data triggers a full parse.

## Step4 Design

JApiCmp is currently invoked once per changed dependency pair. Add a persistent
comparison cache keyed by old JAR SHA-256, new JAR SHA-256, JApiCmp tool SHA-256,
JApiCmp version/options, target JDK, and cache schema version. Cache the raw XML
and normalized API rows together with their integrity hash. The normalized rows
must pass the same parser and validation contract as fresh results.

Memoize the JApiCmp tool digest within one process. Keep bounded dependency
parallelism, deterministic result merging, and fail-closed behavior. A Java
process failure, timeout, or partial output is never cached as a successful
comparison.

## Step5 Design

Persist artifact class catalogs and member-candidate indexes by artifact
SHA-256, target JDK, parser schema, and scope identity. Index entries contain
only candidate-selection facts; selected classes still pass through the normal
classfile/javap parser and evidence validation path.

Reduce retained memory by interning repeated immutable identities, releasing
temporary candidate lists after deterministic merge, and avoiding duplicate
full edge representations where the physical-edge ledger already owns the
canonical record. Framework and reflection expansion remains target complete;
no depth, class, edge, or time cap may silently truncate analysis.

## Verification

Each optimization follows test-first development:

1. unit tests prove cache identity, invalidation, corruption fallback, and exact
   output parity;
2. focused Step1/Step4/Step5 suites pass;
3. the complete unit suite passes;
4. pinned real-project cases compare canonical before/after outputs per API and
   physical edge;
5. every configured fault injection is still detected;
6. cold and warm performance measurements are recorded, including peak RSS;
7. the release quality gate remains blocking on any correctness or performance
   scope regression.

## Delivery Sequence

1. observability and parity harness;
2. Step1 streaming nested-JAR inspection and inventory cache;
3. Step4 tool-digest and comparison cache;
4. Step5 persisted candidate index and retained-memory reductions;
5. full real-project correctness and performance gate.

Each phase is independently reviewable and revertible. A later phase does not
depend on accepting a measured regression from an earlier phase.

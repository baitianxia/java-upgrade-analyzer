# Cache Evidence Correctness Remediation Design

## Goal

Close the correctness gaps found in the performance optimization review without
removing the measured performance gains. A cache hit is valid only when both its
input identity and the completeness of the evidence producer are proven.

## Invariants

1. Incomplete scans are never persisted as reusable successful evidence.
2. Missing artifacts, parser failures, scan limits, and stale output files fail
   closed to recomputation or an explicit incomplete result.
3. Cache identity includes every conclusion-relevant artifact, parser/tool
   version, option, target JDK, and effective Java runtime identity.
4. Cached machine evidence is revalidated through the normal parser before it
   is returned.
5. Parallel collection is sorted by a complete physical-edge identity before
   deduplication; completion order cannot select the retained edge.
6. Cache failures remain diagnostics and never replace analysis failures.

## Step1

Archive scanning will return rows plus explicit completeness and failure
metadata. Empty successful archives remain distinguishable from read failures.
Only complete scans with valid rows may be cached. Embedded metadata read
failures remain visible and prevent cache publication. Observability records
archive bytes and nested-entry counts in addition to RSS and cache counters.

## Step4

JApiCmp comparison identity will include the configured target JDK and the
effective Java executable/runtime identity. The JApiCmp tool content is hashed
for every comparison identity calculation instead of trusting mutable file
metadata. Before every uncached invocation, the expected XML output is removed;
a successful process must create a new parseable XML document. Cache hits write
the XML, parse it through the production parser, and require canonical equality
with the stored rows. Process metrics report whether Java was actually invoked.

## Step5

The runtime member index records missing coordinates and JARs as blocking index
failures, marks the index incomplete, and does not persist it. Query code falls
back to the exhaustive light scan when the index is incomplete. Business
bytecode caches are published only after every selected class was processed
without scan-limit or parser failures. Batch hit collection sorts and deduplicates
with the complete physical-edge identity, including artifact entry, descriptors,
opcode, instruction offset, edge role, and multi-release version.

## Verification

Each defect receives a failing regression test before production changes. Final
acceptance requires focused suites, the complete unit suite, cold/warm real
project parity including API conclusions and physical-edge ledgers, fault
injection, the Step5 quality gate, and a clean Git worktree.

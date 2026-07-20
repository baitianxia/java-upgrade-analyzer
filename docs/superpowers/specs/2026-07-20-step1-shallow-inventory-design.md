# Step1 Shallow Dependency Inventory Design

## Scope

This change fixes two Step1 responsibilities only:

1. Repeated Maven metadata inside a nested dependency JAR must not by itself
   block dependency discovery.
2. Step1 must not recursively read every class and resource in nested JARs
   when it only needs the packaged dependency inventory.

The generic full-archive safety policy used by stages that consume class or
resource bytes remains unchanged.

## Rejected Approaches

- Raising the aggregate archive-entry limit from 100,000 to 200,000 is a
  project-specific threshold patch and does not remove Step1's unnecessary
  recursive work.
- Ignoring every duplicate below `META-INF/maven/` without parsing each
  occurrence can hide contradictory metadata and parser-order differences.
- Treating contradictory embedded metadata as an API-level `uncertain`
  result mixes artifact identity with call-chain evidence.

## Selected Architecture

Step1 owns a shallow dependency-container scan:

1. Open the outer JAR/WAR and inspect its central-directory names.
2. Reject unsafe outer paths and duplicate physical dependency paths.
3. Select only JAR entries below `BOOT-INF/lib/`, `WEB-INF/lib/`, or `lib/`.
4. Stream each selected nested JAR once to compute its SHA-256.
5. Open the nested JAR central directory, but read only standard
   `META-INF/maven/<group>/<artifact>/pom.properties` records.
6. Enumerate duplicate records by `ZipInfo`, not by filename lookup, so every
   physical occurrence is parsed independently.
7. Collapse records that produce the same normalized GAV. If duplicate records
   at the same path disagree, preserve a non-blocking metadata anomaly and use
   the outer filename plus Maven's effective runtime inventory to select the
   unique packaged coordinate.

The final dependency identity remains the combination of outer entry path,
nested JAR SHA-256, and resolved Maven coordinate. Embedded metadata never
overrides the physical packaged artifact version without reconciliation.

## Error Policy

- Unsafe or duplicate outer dependency paths are blocking because they make
  the physical packaged dependency identity ambiguous.
- An unreadable selected nested JAR or unreadable selected Maven metadata is
  blocking for Step1 completeness.
- Duplicate Maven metadata with the same normalized GAV is silently collapsed.
- Duplicate Maven metadata with different GAV declarations is recorded as an
  artifact metadata anomaly, then reconciled by filename and Maven runtime
  evidence. It does not stop bytecode analysis by itself.
- Non-Maven class/resource contents inside nested dependencies are outside
  Step1's responsibility and are not decompressed by this scan.

## Verification

Regression tests must prove:

- duplicate `pom.properties` records with equivalent GAV are accepted;
- contradictory duplicate records are individually observed, recorded, and
  reconciled without becoming an archive-safety failure;
- a nested JAR containing a corrupt class payload still yields its dependency
  coordinate because Step1 never reads that class;
- unsafe outer paths and duplicate outer dependency paths remain blocking;
- the existing Step1 packaged-dependency suite and generic archive-safety suite
  remain green.

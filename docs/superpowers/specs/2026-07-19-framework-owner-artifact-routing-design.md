# Framework Owner Artifact Routing Design

## Problem

Framework collectors discover business methods from every reactor source root, but the
Spring transaction collector verifies every discovered owner against only the
`__business__` artifact. In an executable Spring Boot JAR, reactor library modules are
separate application-owned entries under `BOOT-INF/lib`. Their classes are therefore
absent from `__business__`, and one failed lookup becomes a blocking framework failure
for unrelated APIs.

## Design

Resolve each discovered owner against all SHA-bound, application-owned catalog entries.
An owner is verified with `javap` only against the single artifact inventory containing
that class. Zero matches produce an owner-scoped missing-evidence finding; multiple
matches remain a blocking ambiguity; artifact identity changes remain blocking and
fail closed. External runtime dependencies are never treated as business owners.

The routing helper is shared by framework collectors that need owner-specific artifact
verification. It returns explicit owner-to-entry assignments and structured errors,
instead of copying internal-module classes into `__business__` or adding project names.

## Verification

Add a regression with one transactional owner in `__business__` and another in an
application-owned internal module. Prove the current implementation fails first, then
prove both methods are verified after routing. Add ambiguity and missing-owner cases,
run framework and Step5 suites, run the full suite, and rerun the fixed RuoYi revision
with the independent Oracle and fault-injection gates.

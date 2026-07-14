# MyBatis Proxy Real-Project Audit Design

## Objective

Validate Step5 and the real-project test harness against MyBatis mapper dynamic
proxies using an official, pinned project. Audit every selected API with evidence
that is independent of the analyzer, deliberately damage required evidence to
prove the guard fails, and turn each discovered defect into a focused regression
before changing production code.

## Target Project

Use the `mybatis-spring-boot-4.0.1` release of `mybatis/spring-boot-starter` at
Git revision `bb8bac144e4677cf1bab5a6d27ced2521972adfc`. Audit the two executable
sample artifacts published by the same release to Maven Central:

- `mybatis-spring-boot-sample-annotation`: mapper registration and SQL statement
  binding through `@Mapper` and `@Select` classfile annotations.
- `mybatis-spring-boot-sample-xml`: mapper registration through `@Mapper`, MyBatis
  configuration resources, XML namespace/id statement binding, a direct
  `SqlSession` call, and a mapper proxy call.

Using two artifacts from one pinned repository and release keeps source,
dependencies, and distributed runtime bytes aligned while covering two different
registration mechanisms. The Maven Central SHA-1 sidecars and locally recorded
SHA-256 values authenticate the exact inputs without executing third-party build
logic.

## Considered Approaches

### Annotation Sample Only

This is the smallest target and proves an interface proxy is invoked. It cannot
test XML namespace/id matching or missing-resource failures, so it leaves the most
important configuration-driven false-negative mode untouched.

### XML Sample Only

This covers configuration resources and includes both `SqlSession` and mapper
calls. It cannot prove that annotation metadata is independently inventoried and
would make annotation parsing an untested assumption.

### Paired Annotation and XML Samples

This is the selected approach. It has a slightly larger build and fixture surface,
but produces orthogonal evidence under one revision and allows fault injection at
the bytecode, annotation, and resource layers.

## Evidence Architecture

The analyzer and Oracle must not share a conclusion-producing parser.

### Physical Bytecode Evidence

Use the existing classfile/JDK Oracle to prove application call instructions such
as `CommandLineRunner.run -> CityMapper.findByState` and
`CommandLineRunner.run -> HotelMapper.selectByCityId`. Use `javap -c -p -s` on
the packaged MyBatis classes to prove framework-internal dispatch instructions.
Every selected method target has an exact owner, name, and descriptor.

### Registration Evidence

Add a read-only independent inventory for:

- runtime-visible `@Mapper` and SQL annotations in packaged classfiles;
- `mybatis-config.xml` mapper resource declarations;
- mapper XML `namespace` and statement `id` pairs;
- presence and SHA provenance of every inspected Fat Jar entry.

Resource parsing uses the existing safe XML parser. Annotation evidence comes
from classfile attributes or `javap -v`, not source text.

### Runtime Evidence

Run each published sample against its embedded H2 database and require a successful
exit plus the expected query result. Runtime success proves the proxy and mapping
are activatable for the pinned artifact; it does not replace physical edge or
registration evidence.

### Semantic Links

Represent dynamic links separately from JVM call instructions:

- business `invokeinterface` -> mapper contract;
- mapper contract -> proven MyBatis proxy dispatch;
- mapper method -> annotation or XML statement binding;
- framework dispatch -> selected MyBatis runtime API.

Semantic links must carry artifact SHA, registration source, target identity, and
an authority label. They cannot be rendered as physical bytecode edges.

## Decision Rules

- A physical business call to a mapper method is activation evidence for selected
  MyBatis dependency APIs; the mapper method is not part of the changed denominator.
- A framework-internal MyBatis API is `reachable` only when the complete physical
  business call, registration, binding, proxy dispatch, and runtime activation
  evidence all agree.
- A mapper call with registration but no runtime activation is `uncertain`.
- Missing or malformed required annotation/XML/framework evidence is
  `not_analyzed`, never `not_found_in_static_analysis`.
- A complete scan with no registration or invocation may be
  `not_found_in_static_analysis` only when all relevant evidence layers completed.
- Extra analyzer paths or targets fail the guard just like missing paths or targets.

Final statuses continue to be produced through `step5_evidence_model.py`; scanners
and topology extractors only report facts and failures.

## Exhaustive API Denominator

The selected denominator is declared before reading analyzer output. It contains
only the chosen dependency-owned MyBatis runtime methods. Production mapper
methods invoked by the two sample entry points remain activation evidence. Constructors,
compiler scaffolding, logging, model accessors, and unrelated startup calls are
excluded explicitly in the fixture.

For every row, the fixture records expected status, complete semantic/physical
path, artifact entry, evidence authority, and whether runtime activation is
required. The guard fails if any row is missing, duplicated, unverified, or if the
analyzer reports an undeclared selected target.

## Fault Injection

Create mutated copies of the built artifacts without modifying the target checkout:

1. remove a mapper XML resource;
2. alter a mapper XML namespace or statement id;
3. remove the annotation-evidence entry from the Oracle inventory;
4. remove a required proxy-dispatch semantic link;
5. inject an Oracle timeout or incomplete scan marker.

Each mutation must make the corresponding gate fail with a specific reason. The
tests prove that a passing guard depends on evidence completeness rather than a
hard-coded expected status.

## Performance Gates

Record wall time, inspected class count, inspected resource count, classfile parse
rate, `javap` task count, duplicate artifact scans, and peak resident memory when
available. Apply existing absolute budgets and reject regressions greater than 25%
against the pinned fixture baseline unless the fixture is deliberately re-reviewed.

## Scope Boundaries

- Do not add a MyBatis project-name special case.
- Do not infer SQL execution from source strings alone.
- Do not model configuration links as physical bytecode calls.
- Do not install new runtime dependencies or plugins.
- Do not modify the external project to make the analyzer pass.
- Refactor shared evidence policy only when the real audit demonstrates a general
  ownership, completeness, semantic-link, or decision defect.

## Acceptance Criteria

- Both pinned published sample artifacts pass repository checksum verification and
  execute successfully.
- Every selected API is independently verified; sampling is forbidden.
- Annotation and XML mapper-proxy topologies are both observed.
- Every required fault injection causes a deterministic guard failure.
- Every production defect has a failing focused regression before its fix.
- Existing real-project guards and the full unit suite continue to pass.
- Performance remains within the declared budgets.
- The final commit contains no target-project or generated-report files.

## Validated Outcome

The implementation keeps source parsing as candidate discovery only. A confirmed
mapper-proxy edge now requires registration, annotation/XML binding, and Spring
activation evidence from the SHA-verified final Fat Jar. Application-owned nested
modules under `BOOT-INF/lib` are inspected only after their outer entry and nested
Jar SHA agree; ordinary runtime dependencies are not promoted to business code.

The independent Oracle requires a distinct physical edge for each selected
framework API, including `MapperMethod.execute -> SqlSession.selectOne`. V3 guard
comparison is exact in both directions, so missing and extra semantic references
both fail. Core evidence functions are structurally prohibited from using broad
`except Exception` handlers.

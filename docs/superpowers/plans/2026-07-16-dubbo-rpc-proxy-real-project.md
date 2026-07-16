# Dubbo RPC Proxy Real Project Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add and execute a previously untested Apache Dubbo RPC consumer as a strict real-project discovery case.

**Architecture:** Register the already built Spring Boot Fat Jar as a SHA-verifiable discovery input. Dynamically discover calls to the nested DemoService provider while excluding provider self-references, then reconcile every selected API and physical edge with the final-artifact classfile oracle and JDK javap.

**Tech Stack:** Python unittest, Java classfiles, javap, Spring Boot Fat Jar, Apache Dubbo.

## Global Constraints

- Do not install additional software or execute an unapproved third-party build.
- Use Git revision `fcda5252cdb72a84192aff4387bd336c26b47d5b`.
- Use artifact SHA-256 `14c4bdfa3ed4240152b6216e7d8a7aa7a252e3693b492d262db2a6d3b8449251`.
- Audit every dynamically discovered API and reject missing, extra, conflicting, or unverified conclusions.

---

### Task 1: Register the new real-project case

**Files:**
- Modify: `scripts/real_project_regression.py`
- Test: `tests/test_real_project_regression.py`

**Interfaces:**
- Consumes: `RealProjectCase`, `materialize_bytecode_changed_apis`, final-artifact Oracle.
- Produces: `CASES["dubbo-rpc-proxy-consumer"]`.

- [x] Add a failing configuration test asserting the project root, source directory, target coordinate, owner prefix, artifact path, and required topologies.
- [x] Run the configuration test and confirm it fails because the case is absent.
- [x] Register the case with discovery mode, JDK Oracle, strict Git/Java-file health checks, and the existing Fat Jar.
- [x] Run the configuration and real-project regression test modules.

### Task 2: Execute strict API and edge audit

**Files:**
- Modify only if a failing regression proves a production defect.
- Test: add the smallest regression adjacent to the defective component.

**Interfaces:**
- Consumes: `python3 scripts/real_project_regression.py --case dubbo-rpc-proxy-consumer`.
- Produces: per-API Oracle ledger, edge reconciliation, topology coverage, and performance envelope.

- [x] Run the new real-project case with a dedicated JSON result.
- [x] Verify selected API count equals accounted API count.
- [x] Verify Oracle incorrect, conflict, unverified, missing-edge, and extra-edge counts are zero.
- [x] If any assertion fails, reproduce it in a minimal unit test before changing production code.
- [x] Re-run the case until the defect is fixed or record the exact objective evidence gap.

### Task 3: Final regression and retrospective

**Files:**
- Modify: `TODO.md` only when the audit proves a new unfinished capability.

**Interfaces:**
- Consumes: new case result and existing quality gates.
- Produces: honest completion report with remaining blockers.

- [x] Run the Step5 accuracy benchmark.
- [x] Run the full unit-test suite.
- [x] Run `git diff --check` and Python compilation checks.
- [x] Record new topology coverage, defects found, root cause, and any remaining objective uncertainty.

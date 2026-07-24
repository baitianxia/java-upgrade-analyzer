#!/usr/bin/env python3
"""Resolve auxiliary source refs from live Git remotes without changing user branches."""

from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from compat import git_cmd, run_cmd


_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
_CORE_VERSION_RE = re.compile(r"\d+(?:\.\d+)+")
DEFAULT_FETCH_ATTEMPTS = 3
DEFAULT_FETCH_RETRY_DELAYS = (1, 3)
_REMOTE_REF_ABSENT_RC = 4

_FETCH_AUTH_PATTERNS = (
    "authentication failed", "permission denied", "access denied",
    "could not read username", "terminal prompts disabled", "repository not found",
    "host key verification failed", "publickey",
)
_FETCH_NOT_FOUND_PATTERNS = (
    "couldn't find remote ref", "could not find remote ref", "invalid refspec",
    "not our ref", "unadvertised object", "remote ref no longer exists",
)
_FETCH_TRANSIENT_PATTERNS = (
    "timed out", "timeout", "connection reset", "connection was reset",
    "connection refused", "connection closed", "connection aborted",
    "remote end hung up", "unexpected disconnect", "broken pipe",
    "kex_exchange_identification", "ssh_exchange_identification",
    "banner exchange", "no route to host", "network is unreachable",
    "temporary failure", "temporarily unavailable", "could not resolve host",
    "name or service not known", "http 500", "http 502", "http 503", "http 504",
    "the requested url returned error: 500", "the requested url returned error: 502",
    "the requested url returned error: 503", "the requested url returned error: 504",
    "命令超时", "连接超时", "连接被重置", "连接已关闭", "网络不可达",
)


def _git(repo_dir, *args, timeout=30):
    stdout, stderr, rc = run_cmd(
        git_cmd() + list(args),
        cwd=str(Path(repo_dir).resolve()),
        timeout=timeout,
        env={"GIT_TERMINAL_PROMPT": "0"},
    )
    return str(stdout or "").strip(), str(stderr or "").strip(), rc


def _now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _fingerprint(requested_ref, candidates, failures):
    payload = {
        "requested_ref": str(requested_ref or "").strip(),
        "candidates": candidates or [],
        "failures": failures or [],
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _remote_names(repo_dir):
    stdout, stderr, rc = _git(repo_dir, "remote", timeout=10)
    if rc != 0:
        return [], [{"remote": "", "stage": "list_remotes", "reason": stderr or "git remote failed"}]
    return sorted({line.strip() for line in stdout.splitlines() if line.strip()}), []


def query_live_remote_refs(
    repo_dir,
    timeout=30,
    *,
    retry_attempts=DEFAULT_FETCH_ATTEMPTS,
    retry_delays=DEFAULT_FETCH_RETRY_DELAYS,
):
    """Return branch/tag facts directly reported by every configured remote."""
    names, failures = _remote_names(repo_dir)
    refs = []
    for remote in names:
        attempt_records = []
        stdout = stderr = ""
        rc = 1
        max_attempts = max(1, int(retry_attempts or 1))
        delays = tuple(retry_delays or ())
        for attempt_number in range(1, max_attempts + 1):
            stdout, stderr, rc = _git(repo_dir, "ls-remote", "--heads", "--tags", remote, timeout=timeout)
            if rc == 0:
                break
            failure_type, retryable = classify_fetch_failure(stderr or stdout, rc)
            attempt_records.append({
                "attempt": attempt_number,
                "stage": "ls_remote",
                "status": failure_type,
                "reason": stderr or stdout or f"git ls-remote exited with {rc}",
                "retryable": retryable,
            })
            if not retryable or attempt_number >= max_attempts:
                break
            delay = delays[min(attempt_number - 1, len(delays) - 1)] if delays else 0
            if delay > 0:
                time.sleep(delay)
        if rc != 0:
            last_attempt = attempt_records[-1] if attempt_records else {}
            failures.append({
                "remote": remote,
                "stage": "ls_remote",
                "reason": stderr or f"git ls-remote exited with {rc}",
                "reason_code": str(last_attempt.get("status") or "fetch_failed"),
                "retryable": bool(last_attempt.get("retryable")),
                "attempts": attempt_records,
            })
            continue
        remote_rows = []
        for raw_line in stdout.splitlines():
            parts = raw_line.strip().split(None, 1)
            if len(parts) != 2:
                continue
            remote_rows.append((parts[0], parts[1]))
        peeled_tags = {
            canonical_ref[:-3]: commit
            for commit, canonical_ref in remote_rows
            if canonical_ref.endswith("^{}")
        }
        for commit, canonical_ref in remote_rows:
            if canonical_ref.endswith("^{}"):
                continue
            if canonical_ref.startswith("refs/heads/"):
                ref_kind = "branch"
                short_name = canonical_ref[len("refs/heads/"):]
            elif canonical_ref.startswith("refs/tags/"):
                ref_kind = "tag"
                short_name = canonical_ref[len("refs/tags/"):]
                commit = peeled_tags.get(canonical_ref, commit)
            else:
                continue
            refs.append({
                "remote": remote,
                "ref": f"{remote}/{short_name}",
                "canonical_ref": canonical_ref,
                "short_name": short_name,
                "kind": ref_kind,
                "commit": commit,
            })
    refs.sort(key=lambda row: (row["remote"], row["kind"], row["short_name"], row["commit"]))
    return {"queried_at": _now(), "refs": refs, "failures": failures, "remotes": names}


def _version_boundary_score(candidate_name, requested_ref):
    requested = re.sub(r"(?i)-SNAPSHOT$", "", str(requested_ref or "").strip())
    match = _CORE_VERSION_RE.search(requested)
    if not match:
        return 0
    version = match.group(0).lower()
    text = str(candidate_name or "").lower()
    start = 0
    while True:
        index = text.find(version, start)
        if index < 0:
            return 0
        end = index + len(version)
        start = index + 1
        previous = text[index - 1] if index else ""
        following = text[end] if end < len(text) else ""
        if previous and (previous.isdigit() or previous == "."):
            continue
        if following and following not in "-_/.":
            continue
        return 120


def _matching_remote_candidates(inventory, requested_ref):
    requested = str(requested_ref or "").strip()
    if not requested:
        return []
    remote_names = set(inventory.get("remotes") or [])
    explicit_remote = ""
    explicit_name = requested
    if "/" in requested:
        prefix, remainder = requested.split("/", 1)
        if prefix in remote_names:
            explicit_remote, explicit_name = prefix, remainder
    scored = []
    for candidate in inventory.get("refs") or []:
        if explicit_remote and candidate["remote"] != explicit_remote:
            continue
        if explicit_remote:
            score = 240 if candidate["short_name"] == explicit_name else 0
        elif candidate["short_name"] == requested:
            score = 220
        else:
            score = _version_boundary_score(candidate["short_name"], requested)
        if score:
            scored.append({**candidate, "score": score})
    if not scored:
        return []
    highest = max(row["score"] for row in scored)
    return sorted((row for row in scored if row["score"] == highest), key=lambda row: (row["remote"], row["kind"], row["ref"]))


def _base_result(status, requested_ref, candidates=None, failures=None, queried_at=""):
    candidates = list(candidates or [])
    failures = list(failures or [])
    return {
        "status": status,
        "requested_ref": str(requested_ref or "").strip(),
        "resolved_ref": "",
        "resolved_commit": "",
        "remote": "",
        "remote_ref": "",
        "resolution_mode": "unresolved",
        "candidates": candidates,
        "failures": failures,
        "queried_at": queried_at or _now(),
        "fingerprint": _fingerprint(requested_ref, candidates, failures),
    }


def classify_fetch_failure(reason, rc=None):
    text = str(reason or "").strip().lower()
    if any(pattern in text for pattern in _FETCH_AUTH_PATTERNS):
        return "authentication_failed", False
    if any(pattern in text for pattern in _FETCH_NOT_FOUND_PATTERNS):
        return "remote_ref_not_found", False
    if rc == 124 or any(pattern in text for pattern in _FETCH_TRANSIENT_PATTERNS):
        return "transient_network_failure", True
    return "fetch_failed", False


def _query_remote_candidate_commit(repo_dir, candidate, timeout=30):
    canonical_ref = str((candidate or {}).get("canonical_ref") or "").strip()
    remote = str((candidate or {}).get("remote") or "").strip()
    if not canonical_ref or not remote:
        return "", "remote candidate metadata is incomplete", 2
    stdout, stderr, rc = _git(
        repo_dir,
        "ls-remote",
        remote,
        canonical_ref,
        f"{canonical_ref}^{{}}",
        timeout=timeout,
    )
    if rc != 0:
        return "", stderr or stdout or f"git ls-remote exited with {rc}", rc
    rows = {}
    for raw_line in str(stdout or "").splitlines():
        parts = raw_line.strip().split(None, 1)
        if len(parts) == 2:
            rows[parts[1]] = parts[0]
    commit = rows.get(f"{canonical_ref}^{{}}") or rows.get(canonical_ref) or ""
    if not commit:
        # A successful targeted query with no matching row is the only
        # authoritative "ref disappeared" signal. Keep it distinct from
        # transport/process failures so an intermittent SSH connection can
        # never be promoted to remote_ref_moved by error-text heuristics.
        return "", "remote ref no longer exists", _REMOTE_REF_ABSENT_RC
    return commit, "", 0


def _materialize_remote_candidate_details(
    repo_dir,
    candidate,
    *,
    timeout=60,
    expected_commit="",
    retry_attempts=DEFAULT_FETCH_ATTEMPTS,
    retry_delays=DEFAULT_FETCH_RETRY_DELAYS,
):
    expected_commit = str(expected_commit or (candidate or {}).get("commit") or "").strip()
    attempts = []
    max_attempts = max(1, int(retry_attempts or 1))
    delays = tuple(retry_delays or ())
    for attempt_number in range(1, max_attempts + 1):
        observed_commit, query_error, query_rc = _query_remote_candidate_commit(
            repo_dir, candidate, timeout=min(int(timeout or 60), 30),
        )
        if query_error:
            failure_type, retryable = classify_fetch_failure(query_error, query_rc)
            attempts.append({
                "attempt": attempt_number,
                "stage": "ls_remote_before_fetch",
                "status": failure_type,
                "reason": query_error,
                "retryable": retryable,
            })
            if expected_commit and query_rc == _REMOTE_REF_ABSENT_RC:
                return {
                    "status": "remote_ref_moved",
                    "resolved_commit": "",
                    "expected_commit": expected_commit,
                    "observed_commit": "",
                    "attempts": attempts,
                    "reason": "remote ref disappeared after candidate selection",
                }
        elif expected_commit and observed_commit.lower() != expected_commit.lower():
            attempts.append({
                "attempt": attempt_number,
                "stage": "verify_remote_before_fetch",
                "status": "remote_ref_moved",
                "reason": "remote ref changed after candidate selection",
                "retryable": False,
                "expected_commit": expected_commit,
                "observed_commit": observed_commit,
            })
            return {
                "status": "remote_ref_moved",
                "resolved_commit": "",
                "expected_commit": expected_commit,
                "observed_commit": observed_commit,
                "attempts": attempts,
                "reason": "remote ref changed after candidate selection",
            }
        else:
            if not expected_commit:
                expected_commit = observed_commit
            stdout, stderr, rc = _git(
                repo_dir,
                "fetch",
                "--no-tags",
                "--no-write-fetch-head",
                candidate["remote"],
                candidate["canonical_ref"],
                timeout=timeout,
            )
            if rc == 0:
                after_commit, after_error, after_rc = _query_remote_candidate_commit(
                    repo_dir, candidate, timeout=min(int(timeout or 60), 30),
                )
                if after_error:
                    failure_type, retryable = classify_fetch_failure(after_error, after_rc)
                    attempts.append({
                        "attempt": attempt_number,
                        "stage": "ls_remote_after_fetch",
                        "status": failure_type,
                        "reason": after_error,
                        "retryable": retryable,
                    })
                    if expected_commit and after_rc == _REMOTE_REF_ABSENT_RC:
                        return {
                            "status": "remote_ref_moved",
                            "resolved_commit": "",
                            "expected_commit": expected_commit,
                            "observed_commit": "",
                            "attempts": attempts,
                            "reason": "remote ref disappeared while it was being materialized",
                        }
                elif expected_commit and after_commit.lower() != expected_commit.lower():
                    attempts.append({
                        "attempt": attempt_number,
                        "stage": "verify_remote_after_fetch",
                        "status": "remote_ref_moved",
                        "reason": "remote ref changed while it was being materialized",
                        "retryable": False,
                        "expected_commit": expected_commit,
                        "observed_commit": after_commit,
                    })
                    return {
                        "status": "remote_ref_moved",
                        "resolved_commit": "",
                        "expected_commit": expected_commit,
                        "observed_commit": after_commit,
                        "attempts": attempts,
                        "reason": "remote ref changed while it was being materialized",
                    }
                else:
                    stdout, verify_error, verify_rc = _git(
                        repo_dir,
                        "rev-parse",
                        "--verify",
                        f"{expected_commit}^{{commit}}",
                        timeout=10,
                    )
                    fixed_commit = str(stdout or "").splitlines()[-1].strip() if verify_rc == 0 and stdout else ""
                    if fixed_commit and fixed_commit.lower() == expected_commit.lower():
                        attempts.append({
                            "attempt": attempt_number,
                            "stage": "fetch",
                            "status": "success",
                            "reason": "",
                            "retryable": False,
                        })
                        return {
                            "status": "remote_source_resolved",
                            "resolved_commit": fixed_commit,
                            "expected_commit": expected_commit,
                            "observed_commit": after_commit,
                            "attempts": attempts,
                            "reason": "",
                        }
                    reason = verify_error or "fetched object is not the expected commit"
                    attempts.append({
                        "attempt": attempt_number,
                        "stage": "verify_commit",
                        "status": "commit_verification_failed",
                        "reason": reason,
                        "retryable": False,
                    })
                    retryable = False
            else:
                reason = stderr or stdout or f"git fetch exited with {rc}"
                failure_type, retryable = classify_fetch_failure(reason, rc)
                attempts.append({
                    "attempt": attempt_number,
                    "stage": "fetch",
                    "status": failure_type,
                    "reason": reason,
                    "retryable": retryable,
                })

        if not attempts[-1].get("retryable") or attempt_number >= max_attempts:
            break
        delay = delays[min(attempt_number - 1, len(delays) - 1)] if delays else 0
        if delay > 0:
            time.sleep(delay)

    last = attempts[-1] if attempts else {}
    return {
        "status": "remote_fetch_failed",
        "resolved_commit": "",
        "expected_commit": expected_commit,
        "observed_commit": "",
        "attempts": attempts,
        "reason": str(last.get("reason") or "remote fetch failed"),
        "failure_type": str(last.get("status") or "fetch_failed"),
        "retryable": bool(last.get("retryable")),
    }


def _materialize_remote_candidate(repo_dir, candidate, timeout=60):
    result = _materialize_remote_candidate_details(repo_dir, candidate, timeout=timeout)
    return str(result.get("resolved_commit") or ""), str(result.get("reason") or "")


def materialize_remote_source_candidate(
    repo_dir,
    candidate,
    timeout=60,
    *,
    expected_commit="",
    retry_attempts=DEFAULT_FETCH_ATTEMPTS,
    retry_delays=DEFAULT_FETCH_RETRY_DELAYS,
):
    """Fetch one live-remote candidate and return an immutable source record."""
    materialized = _materialize_remote_candidate_details(
        repo_dir,
        candidate,
        timeout=timeout,
        expected_commit=expected_commit,
        retry_attempts=retry_attempts,
        retry_delays=retry_delays,
    )
    fixed_commit = str(materialized.get("resolved_commit") or "")
    if not fixed_commit:
        attempts = list(materialized.get("attempts") or [])
        last_attempt = attempts[-1] if attempts else {}
        return {
            "status": str(materialized.get("status") or "remote_fetch_failed"),
            "resolved_commit": "",
            "expected_commit": str(materialized.get("expected_commit") or ""),
            "observed_commit": str(materialized.get("observed_commit") or ""),
            "attempts": attempts,
            "failure": {
                "remote": str((candidate or {}).get("remote") or ""),
                "stage": str(last_attempt.get("stage") or "fetch"),
                "reason": str(materialized.get("reason") or "remote fetch failed"),
                "reason_code": str(materialized.get("failure_type") or materialized.get("status") or "fetch_failed"),
                "retryable": bool(materialized.get("retryable")),
            },
        }
    return {
        "status": "remote_source_resolved",
        "resolved_ref": str(candidate.get("ref") or ""),
        "resolved_commit": fixed_commit,
        "remote": str(candidate.get("remote") or ""),
        "remote_ref": str(candidate.get("canonical_ref") or ""),
        "resolution_mode": "live_remote",
        "expected_commit": str(materialized.get("expected_commit") or fixed_commit),
        "attempts": list(materialized.get("attempts") or []),
    }


def resolve_remote_source_ref(
    repo_dir,
    requested_ref,
    query_timeout=30,
    fetch_timeout=60,
    *,
    expected_commit="",
):
    """Resolve a requested ref from live remotes and fetch its immutable commit."""
    inventory = query_live_remote_refs(repo_dir, timeout=query_timeout)
    candidates = _matching_remote_candidates(inventory, requested_ref)
    expected_commit = str(expected_commit or "").strip()
    requested_text = str(requested_ref or "").strip()
    explicit_remote = ""
    if "/" in requested_text:
        prefix = requested_text.split("/", 1)[0]
        if prefix in set(inventory.get("remotes") or []):
            explicit_remote = prefix
    relevant_failures = [
        failure for failure in (inventory.get("failures") or [])
        if not explicit_remote or str(failure.get("remote") or "") in {"", explicit_remote}
    ]
    if relevant_failures:
        return _base_result(
            "remote_query_failed",
            requested_ref,
            candidates,
            relevant_failures,
            inventory["queried_at"],
        )
    if expected_commit and candidates:
        expected_candidates = [
            row for row in candidates
            if str(row.get("commit") or "").lower() == expected_commit.lower()
        ]
        if not expected_candidates:
            result = _base_result(
                "remote_ref_moved",
                requested_ref,
                candidates,
                inventory["failures"],
                inventory["queried_at"],
            )
            result.update({
                "expected_commit": expected_commit,
                "observed_commit": str(candidates[0].get("commit") or ""),
            })
            return result
        candidates = expected_candidates
    commits = {row["commit"] for row in candidates}
    if len(commits) > 1:
        return _base_result(
            "remote_source_ambiguous",
            requested_ref,
            candidates,
            inventory["failures"],
            inventory["queried_at"],
        )
    if not candidates:
        failures = list(inventory["failures"])
        if failures:
            return _base_result(
                "remote_query_failed",
                requested_ref,
                [],
                failures,
                inventory["queried_at"],
            )
        if expected_commit:
            result = _base_result(
                "remote_ref_moved",
                requested_ref,
                [],
                [],
                inventory["queried_at"],
            )
            result.update({"expected_commit": expected_commit, "observed_commit": ""})
            return result
        if not inventory["remotes"]:
            failures.append({"remote": "", "stage": "resolve", "reason": "repository has no configured remote"})
        elif not failures:
            failures.append({"remote": "", "stage": "resolve", "reason": "requested ref was not found on a live remote"})
        return _base_result("remote_source_unavailable", requested_ref, [], failures, inventory["queried_at"])

    selected = candidates[0]
    materialized = materialize_remote_source_candidate(
        repo_dir,
        selected,
        timeout=fetch_timeout,
        expected_commit=expected_commit or str(selected.get("commit") or ""),
    )
    fixed_commit = str(materialized.get("resolved_commit") or "")
    if not fixed_commit:
        observed_commit = str(materialized.get("observed_commit") or "")
        if materialized.get("status") == "remote_ref_moved":
            candidates = [
                ({**row, "commit": observed_commit} if observed_commit else None)
                if row.get("remote") == selected.get("remote")
                and row.get("canonical_ref") == selected.get("canonical_ref")
                else row
                for row in candidates
            ]
            candidates = [row for row in candidates if row is not None]
        failures = list(inventory["failures"])
        failure = dict(materialized.get("failure") or {})
        failures.append({
            "remote": selected["remote"],
            "stage": "fetch",
            "reason": str(failure.get("reason") or "remote fetch failed"),
            "reason_code": str(failure.get("reason_code") or materialized.get("status") or "fetch_failed"),
            "attempts": list(materialized.get("attempts") or []),
        })
        result = _base_result(
            str(materialized.get("status") or "remote_fetch_failed"),
            requested_ref,
            candidates,
            failures,
            inventory["queried_at"],
        )
        result.update({
            "expected_commit": str(materialized.get("expected_commit") or selected.get("commit") or ""),
            "observed_commit": observed_commit,
            "attempts": list(materialized.get("attempts") or []),
        })
        return result

    result = _base_result("remote_source_resolved", requested_ref, candidates, inventory["failures"], inventory["queried_at"])
    result.update({
        "resolved_ref": selected["ref"],
        "resolved_commit": fixed_commit,
        "remote": selected["remote"],
        "remote_ref": selected["canonical_ref"],
        "resolution_mode": "live_remote",
        "expected_commit": str(materialized.get("expected_commit") or fixed_commit),
        "attempts": list(materialized.get("attempts") or []),
    })
    return result


def _verify_local_commit(repo_dir, requested_ref):
    requested = str(requested_ref or "").strip()
    candidates = []
    if requested.startswith("refs/"):
        candidates.append(requested)
    else:
        candidates.extend((f"refs/heads/{requested}", f"refs/tags/{requested}"))
        if "/" in requested:
            candidates.append(f"refs/remotes/{requested}")
    if requested == "HEAD" or _COMMIT_RE.fullmatch(requested):
        candidates.append(requested)
    for candidate in candidates:
        stdout, _stderr, rc = _git(repo_dir, "rev-parse", "--verify", f"{candidate}^{{commit}}", timeout=10)
        if rc == 0 and stdout:
            return stdout.splitlines()[-1].strip()
    return ""


def resolve_local_source_ref(
    repo_dir,
    requested_ref,
    *,
    allow_local_source=False,
    allow_dirty_local_source=False,
):
    """Resolve a local ref only after explicit confirmation."""
    commit = _verify_local_commit(repo_dir, requested_ref)
    stdout, _stderr, rc = _git(repo_dir, "status", "--porcelain", timeout=10)
    dirty = rc == 0 and bool(stdout.strip())
    if not allow_local_source:
        result = _base_result("awaiting_local_source_confirmation", requested_ref)
        result.update({"local_candidate_commit": commit, "dirty": dirty})
        return result
    if not commit:
        result = _base_result("remote_source_unavailable", requested_ref)
        result.update({"dirty": dirty, "failures": [{"stage": "local_resolve", "reason": "confirmed local ref was not found"}]})
        return result
    if dirty and not allow_dirty_local_source:
        result = _base_result("awaiting_dirty_local_source_confirmation", requested_ref)
        result.update({"local_candidate_commit": commit, "dirty": True})
        return result
    result = _base_result("user_confirmed_local_source", requested_ref)
    result.update({
        "resolved_ref": str(requested_ref or "").strip(),
        "resolved_commit": commit,
        "resolution_mode": "user_confirmed_local_source",
        "dirty": dirty,
    })
    return result


__all__ = [
    "classify_fetch_failure",
    "query_live_remote_refs",
    "materialize_remote_source_candidate",
    "resolve_local_source_ref",
    "resolve_remote_source_ref",
]

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


_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
_CORE_VERSION_RE = re.compile(r"\d+(?:\.\d+)+")
DEFAULT_FETCH_ATTEMPTS = 3
DEFAULT_FETCH_RETRY_DELAYS = (1, 3)
_LOCAL_DISCOVERY_RETRY_DELAYS = (0.05, 0.15)

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
    "closed by remote host", "failed to connect", "could not connect",
    "remote end hung up", "unexpected disconnect", "broken pipe",
    "kex_exchange_identification", "ssh_exchange_identification",
    "banner exchange", "no route to host", "network is unreachable",
    "temporary failure", "temporarily unavailable", "could not resolve host",
    "could not resolve proxy", "failed to connect to proxy",
    "proxy connect aborted", "proxy error", "empty reply from server",
    "tls connection was non-properly terminated", "ssl_error_syscall",
    "error in the pull function", "failed to receive handshake",
    "ssl_read", "gnutls_recv error", "tls connect error", "unexpected eof",
    "early eof", "http/2 stream", "http2 framing layer", "transfer closed",
    "another git process", "index-pack failed", "cannot lock ref",
    "unable to create", ".lock': file exists", ".lock\" already exists",
    "name or service not known", "http 500", "http 502", "http 503", "http 504",
    "the requested url returned error: 500", "the requested url returned error: 502",
    "the requested url returned error: 503", "the requested url returned error: 504",
    "命令超时", "连接超时", "连接被重置", "连接已关闭", "网络不可达",
)
_FETCH_TERMINAL_HTTP_RE = re.compile(
    r"(?:requested url returned error|http(?:/\d(?:\.\d)?)?)\s*:?\s*(?:401|403|404|407)\b",
    re.IGNORECASE,
)
_FETCH_TRANSIENT_HTTP_RE = re.compile(
    r"(?:requested url returned error|http(?:/\d(?:\.\d)?)?)\s*:?\s*"
    r"(?:408|425|429|5\d\d)\b",
    re.IGNORECASE,
)
_FULL_OBJECT_RE = re.compile(r"^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$")
_DEADLINE_FAILURE = "remote_operation_deadline_exceeded"
_LOCAL_REF_ABSENT_PATTERNS = (
    "needed a single revision",
    "unknown revision or path not in the working tree",
    "ambiguous argument",
    "bad revision",
    "not a valid object name",
    "不是一个有效的对象名",
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


def _parse_remote_rows(stdout):
    """Parse trustworthy ls-remote rows and retain malformed output evidence."""
    rows = []
    malformed = []
    for raw_line in str(stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if (
            len(parts) != 2
            or not _FULL_OBJECT_RE.fullmatch(parts[0])
            or not parts[1].startswith("refs/")
        ):
            malformed.append(line)
            continue
        rows.append((parts[0], parts[1]))
    return rows, malformed


def _empty_observation_signature(stdout):
    lines = [line.strip() for line in str(stdout or "").splitlines() if line.strip()]
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def _absence_observation_failure(observations):
    """Return an error when rc=0 output does not prove repeated absence."""
    observations = list(observations or [])
    if (
        len(observations) >= 2
        and all(item.get("status") == "remote_ref_observation_empty" for item in observations)
        and len({item.get("signature") for item in observations}) == 1
    ):
        return None
    if any(item.get("status") == "remote_ref_observation_malformed" for item in observations):
        return (
            "remote_ref_observation_malformed",
            "remote repeatedly returned malformed ref output; absence cannot be established",
        )
    if any(item.get("status") == "remote_ref_observation_unexpected" for item in observations):
        return (
            "remote_ref_observation_unexpected",
            "remote returned refs outside the exact requested identity; absence cannot be established",
        )
    if len(observations) < 2:
        return (
            "remote_ref_observation_unconfirmed",
            "remote ref absence was observed only once",
        )
    return (
        "inconsistent_remote_ref_observation",
        "remote returned inconsistent empty or malformed ref observations",
    )


def _retry_delay(delays, attempt_number):
    if not delays:
        return 0
    base = max(0.0, float(delays[min(attempt_number - 1, len(delays) - 1)]))
    if not base:
        return 0
    # Small deterministic jitter prevents concurrent analyses from retrying a
    # shared remote in lockstep while keeping the behavior reproducible.
    jitter = min(0.05, base * 0.05) * ((int(attempt_number) % 3) + 1) / 3
    return base + jitter


def _new_deadline(*timeouts):
    budget = sum(max(0.0, float(value or 0)) for value in timeouts)
    return time.monotonic() + budget


def _remaining_timeout(deadline, cap):
    cap = max(0.0, float(cap or 0))
    if deadline is None:
        return cap
    remaining = float(deadline) - time.monotonic()
    if remaining <= 0:
        return 0
    return cap if remaining >= cap else remaining


def _sleep_before_retry(delays, attempt_number, *, deadline=None):
    delay = _retry_delay(delays, attempt_number)
    if delay <= 0:
        return True
    if deadline is not None and _remaining_timeout(deadline, delay) < delay:
        return False
    time.sleep(delay)
    return True


def _parse_remote_names(stdout):
    return sorted({line.strip() for line in str(stdout or "").splitlines() if line.strip()})


def _parse_remote_url_keys(stdout):
    names = []
    malformed = []
    for raw_line in str(stdout or "").splitlines():
        line = raw_line.strip()
        key = line.split(None, 1)[0] if line else ""
        if not key:
            continue
        match = re.fullmatch(r"remote\.(.+)\.url", key, re.IGNORECASE)
        if not match or not match.group(1).strip():
            malformed.append(key)
            continue
        names.append(match.group(1).strip())
    return sorted(set(names)), malformed


def _remote_discovery_failure(repo_dir, reason, *, attempts=None, inconsistent=False):
    normalized_reason = str(reason or "").lower()
    if "total remote resolution deadline" in normalized_reason:
        reason_code = _DEADLINE_FAILURE
    elif (
        "not a git repository" in normalized_reason
        or "不是一个 git 仓库" in normalized_reason
        or "不是 git 仓库" in normalized_reason
    ):
        reason_code = "repository_not_git"
    else:
        reason_code = "local_remote_discovery_failed"
    return [], [{
        "remote": "",
        "stage": "list_remotes",
        "reason": str(reason or "git remote discovery failed"),
        "reason_code": reason_code,
        "repository_path": str(Path(repo_dir).resolve()),
        "observation_status": "inconsistent" if inconsistent else "failed",
        "attempts": list(attempts or []),
    }]


def _remote_names(repo_dir, *, deadline=None):
    """List repository-local remotes with an independent local-config proof.

    `git remote` reads inherited config scopes, so even a first successful
    non-empty observation is cross-checked against `git config --local`.
    """
    attempts = []
    observations = []
    for attempt_number in range(1, DEFAULT_FETCH_ATTEMPTS + 1):
        attempt_timeout = _remaining_timeout(deadline, 10)
        if attempt_timeout <= 0:
            return _remote_discovery_failure(
                repo_dir,
                "the total remote resolution deadline was exhausted",
                attempts=attempts,
            )
        stdout, stderr, rc = _git(repo_dir, "remote", timeout=attempt_timeout)
        names = _parse_remote_names(stdout) if rc == 0 else []
        observation = {
            "attempt": attempt_number,
            "stage": "git_remote",
            "status": (
                "success"
                if rc == 0 and names
                else ("empty" if rc == 0 else "failed")
            ),
            "remotes": names,
            "reason": "" if rc == 0 else str(stderr or stdout or "git remote failed"),
            "return_code": rc,
        }
        observations.append(observation)
        attempts.append(dict(observation))
        successful_so_far = [
            item for item in observations if item["return_code"] == 0
        ]
        if rc == 0 and names:
            break
        if rc == 0 and not names and sum(
            1 for item in successful_so_far if not item["remotes"]
        ) >= 2:
            break

    successful = [item for item in observations if item["return_code"] == 0]
    nonempty_sets = {
        tuple(item["remotes"])
        for item in successful
        if item["remotes"]
    }
    # An empty remote list is consequential: it becomes
    # remote_configuration_missing upstream. Cross-check the underlying URL
    # configuration, and require at least two successful empty listings before
    # accepting that conclusion.
    config_stdout = config_stderr = ""
    config_rc = -1
    config_names = []
    malformed_config = []
    config_no_match = False
    config_valid = False
    for attempt_number in range(1, DEFAULT_FETCH_ATTEMPTS + 1):
        config_timeout = _remaining_timeout(deadline, 10)
        if config_timeout <= 0:
            return _remote_discovery_failure(
                repo_dir,
                "the total remote resolution deadline was exhausted",
                attempts=attempts,
            )
        config_stdout, config_stderr, config_rc = _git(
            repo_dir,
            "config",
            "--local",
            "--includes",
            "--get-regexp",
            r"^remote\..*\.url$",
            timeout=config_timeout,
        )
        config_names, malformed_config = _parse_remote_url_keys(config_stdout)
        # `git config --get-regexp` uses rc=1 with no output when no key
        # matches. This is the only terminal observation that proves there is
        # no repository-local remote URL; all other failed/incomplete reads
        # may be transient and are retried within the caller's deadline.
        config_no_match = config_rc == 1 and not config_stdout and not config_stderr
        config_valid = (
            (config_rc == 0 and bool(config_names) and not malformed_config)
            or config_no_match
        )
        config_reason = str(
            config_stderr
            or "\n".join(malformed_config)
            or config_stdout
            or f"git config exited with {config_rc}"
        )
        attempts.append({
            "attempt": attempt_number,
            "stage": "git_config_remote_urls",
            "status": "success" if config_valid else "failed",
            "remotes": config_names,
            "reason": "" if config_valid else config_reason,
            "return_code": config_rc,
        })
        if config_valid or attempt_number >= DEFAULT_FETCH_ATTEMPTS:
            break
        if not _sleep_before_retry(
            _LOCAL_DISCOVERY_RETRY_DELAYS,
            attempt_number,
            deadline=deadline,
        ):
            return _remote_discovery_failure(
                repo_dir,
                "the total remote resolution deadline was exhausted",
                attempts=attempts,
            )

    empty_reads = sum(1 for item in successful if not item["remotes"])
    if config_valid and config_names:
        # Repository-local configuration is the authoritative source. A
        # successful local read also repairs a transient empty `git remote`
        # observation instead of converting it into a user-facing blocker.
        return config_names, []
    if config_no_match and nonempty_sets:
        # `git remote` reads all config scopes; names injected through global or
        # system config are not remotes configured for this repository.
        return [], []
    if not nonempty_sets and empty_reads >= 2 and config_no_match:
        return [], []
    reason_parts = [
        "remote discovery observations were inconsistent",
        f"git remote observations={[item['remotes'] for item in observations]}",
        f"configured remote URLs={config_names}",
    ]
    reason_parts.extend(
        str(item.get("reason") or "")
        for item in observations
        if item.get("reason")
    )
    if not config_valid:
        reason_parts.append(str(config_stderr or config_stdout or f"git config exited with {config_rc}"))
    return _remote_discovery_failure(
        repo_dir,
        "; ".join(part for part in reason_parts if part),
        attempts=attempts,
        inconsistent=True,
    )


def query_live_remote_refs(
    repo_dir,
    timeout=30,
    *,
    retry_attempts=DEFAULT_FETCH_ATTEMPTS,
    retry_delays=DEFAULT_FETCH_RETRY_DELAYS,
    deadline=None,
):
    """Return broad branch/tag facts for dependency and explicit-SHA matching."""
    # Step4 invokes this function directly. In that standalone mode `timeout`
    # is the budget for the entire multi-remote inventory, not a fresh budget
    # for every remote and retry.
    if deadline is None:
        deadline = _new_deadline(timeout)
    names, failures = _remote_names(repo_dir, deadline=deadline)
    # The default remote is the highest-value broad probe. Querying it first
    # prevents an unrelated slow peer remote from consuming the shared budget
    # before origin can be observed.
    names = sorted(names, key=lambda name: (name != "origin", name))
    refs = []
    for remote in names:
        attempt_records = []
        stdout = stderr = ""
        rc = 1
        remote_rows = []
        absence_observations = []
        max_attempts = max(1, int(retry_attempts or 1))
        delays = tuple(retry_delays or ())
        for attempt_number in range(1, max_attempts + 1):
            attempt_timeout = _remaining_timeout(deadline, timeout)
            if attempt_timeout <= 0:
                rc = 1
                stderr = "the total remote resolution deadline was exhausted"
                attempt_records.append({
                    "attempt": attempt_number,
                    "stage": "ls_remote",
                    "status": _DEADLINE_FAILURE,
                    "reason": stderr,
                    "retryable": False,
                })
                break
            stdout, stderr, rc = _git(
                repo_dir,
                "ls-remote",
                "--heads",
                "--tags",
                remote,
                timeout=attempt_timeout,
            )
            if rc == 0:
                remote_rows, malformed = _parse_remote_rows(stdout)
                if remote_rows and not malformed:
                    attempt_records.append({
                        "attempt": attempt_number,
                        "stage": "ls_remote",
                        "status": "success",
                        "reason": "",
                        "retryable": False,
                    })
                    break
                observation_status = (
                    "remote_ref_observation_malformed"
                    if malformed
                    else "remote_ref_observation_empty"
                )
                absence_observations.append({
                    "status": observation_status,
                    "signature": _empty_observation_signature(stdout),
                })
                attempt_records.append({
                    "attempt": attempt_number,
                    "stage": "ls_remote",
                    "status": observation_status,
                    "reason": "\n".join(malformed) if malformed else "remote returned no refs",
                    "retryable": attempt_number < max_attempts,
                })
                observation_failure = _absence_observation_failure(
                    absence_observations,
                )
                if observation_failure is None:
                    break
                if attempt_number >= max_attempts:
                    rc = 1
                    failure_type, stderr = observation_failure
                    attempt_records[-1].update({
                        "status": failure_type,
                        "reason": stderr,
                        "retryable": False,
                    })
                    break
            else:
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
            if not _sleep_before_retry(
                delays,
                attempt_number,
                deadline=deadline,
            ):
                rc = 1
                stderr = "the total remote resolution deadline was exhausted"
                attempt_records.append({
                    "attempt": attempt_number,
                    "stage": "ls_remote_retry_wait",
                    "status": _DEADLINE_FAILURE,
                    "reason": stderr,
                    "retryable": False,
                })
                break
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
    if _FETCH_TERMINAL_HTTP_RE.search(text):
        return "authentication_failed", False
    if any(pattern in text for pattern in _FETCH_NOT_FOUND_PATTERNS):
        return "remote_ref_not_found", False
    if (
        rc in {-1, 124}
        or _FETCH_TRANSIENT_HTTP_RE.search(text)
        or any(pattern in text for pattern in _FETCH_TRANSIENT_PATTERNS)
    ):
        return "transient_network_failure", True
    # Remote read/fetch operations are idempotent and bounded by the caller's
    # attempt limit. Unknown Git/SSH/cURL failures are therefore safer to retry
    # than to turn one transport-specific wording into a permanent blocker.
    return "fetch_failed", True


def _verify_commit_object(repo_dir, commit, *, timeout=10, deadline=None):
    """Return the immutable commit only when the object is present locally."""
    expected = str(commit or "").strip()
    if not expected:
        return ""
    verify_timeout = _remaining_timeout(deadline, timeout)
    if verify_timeout <= 0:
        return ""
    stdout, _stderr, rc = _git(
        repo_dir,
        "rev-parse",
        "--verify",
        f"{expected}^{{commit}}",
        timeout=verify_timeout,
    )
    fixed_commit = str(stdout or "").splitlines()[-1].strip() if rc == 0 and stdout else ""
    return fixed_commit if fixed_commit.lower() == expected.lower() else ""


def _fetch_expected_commit(repo_dir, candidate, expected_commit, timeout=60):
    """Try to materialize the already-pinned SHA without following a moving ref."""
    expected = str(expected_commit or "").strip()
    remote = str((candidate or {}).get("remote") or "").strip()
    if not remote or not expected:
        return {
            "status": "remote_expected_commit_unmaterializable",
            "target": expected,
            "failure_type": "fetch_failed",
            "reason": "remote or expected commit is missing",
            "retryable": False,
        }
    stdout, stderr, rc = _git(
        repo_dir,
        "fetch",
        "--no-tags",
        "--no-write-fetch-head",
        remote,
        expected,
        timeout=timeout,
    )
    if rc == 0:
        return {
            "status": "success",
            "target": expected,
            "failure_type": "",
            "reason": "",
            "retryable": False,
        }
    reason = stderr or stdout or f"git fetch exited with {rc}"
    failure_type, retryable = classify_fetch_failure(reason, rc)
    return {
        "status": "remote_expected_commit_unmaterializable",
        "target": expected,
        "failure_type": failure_type,
        "reason": reason,
        "retryable": retryable,
    }


def materialize_remote_source_candidate(
    repo_dir,
    candidate,
    timeout=60,
    *,
    expected_commit="",
    retry_attempts=DEFAULT_FETCH_ATTEMPTS,
    retry_delays=DEFAULT_FETCH_RETRY_DELAYS,
):
    """Materialize one already-advertised immutable candidate.

    The candidate's SHA was established by the live remote query. Fetching a
    canonical ref is only a way to transfer that object; a later branch move
    cannot invalidate the pinned SHA. The total `timeout` is shared by all
    canonical-ref and exact-SHA attempts.
    """
    selected_commit = str(
        expected_commit or (candidate or {}).get("commit") or ""
    ).strip()
    deadline = _new_deadline(timeout)
    materialized = _materialize_targeted_commit(
        repo_dir,
        candidate,
        selected_commit,
        timeout=timeout,
        pinned=bool(str(expected_commit or "").strip()),
        retry_attempts=retry_attempts,
        retry_delays=retry_delays,
        deadline=deadline,
    )
    fixed_commit = str(materialized.get("resolved_commit") or "")
    if not fixed_commit:
        attempts = list(materialized.get("attempts") or [])
        last_attempt = attempts[-1] if attempts else {}
        return {
            "status": str(materialized.get("status") or "remote_fetch_failed"),
            "resolved_commit": "",
            "expected_commit": str(materialized.get("expected_commit") or ""),
            "observed_commit": "",
            "attempts": attempts,
            "failure": {
                **dict(materialized.get("failure") or {}),
                "remote": str(
                    (materialized.get("failure") or {}).get("remote")
                    or (candidate or {}).get("remote")
                    or ""
                ),
                "stage": str(
                    (materialized.get("failure") or {}).get("stage")
                    or last_attempt.get("stage")
                    or "fetch"
                ),
                "reason": str(
                    (materialized.get("failure") or {}).get("reason")
                    or "remote fetch failed"
                ),
                "reason_code": str(
                    (materialized.get("failure") or {}).get("reason_code")
                    or materialized.get("status")
                    or "fetch_failed"
                ),
                "retryable": bool(
                    (materialized.get("failure") or {}).get("retryable")
                ),
            },
        }
    return {
        "status": "remote_source_resolved",
        "resolved_ref": str(candidate.get("ref") or ""),
        "resolved_commit": fixed_commit,
        "remote": str(candidate.get("remote") or ""),
        "remote_ref": str(candidate.get("canonical_ref") or ""),
        "resolution_mode": str(materialized.get("resolution_mode") or "live_remote"),
        "expected_commit": str(materialized.get("expected_commit") or fixed_commit),
        "observed_commit": "",
        "attempts": list(materialized.get("attempts") or []),
    }


def _targeted_remote_ref_inventory(
    repo_dir,
    remote,
    short_name,
    *,
    canonical_ref="",
    timeout=30,
    retry_attempts=DEFAULT_FETCH_ATTEMPTS,
    retry_delays=DEFAULT_FETCH_RETRY_DELAYS,
    deadline=None,
):
    """Query only the requested branch/tag instead of enumerating a remote."""
    remote = str(remote or "").strip()
    short_name = str(short_name or "").strip()
    canonical_ref = str(canonical_ref or "").strip()
    patterns = []
    if canonical_ref:
        patterns.append(canonical_ref)
        if canonical_ref.startswith("refs/tags/"):
            patterns.append(f"{canonical_ref}^{{}}")
    else:
        patterns.extend((
            f"refs/heads/{short_name}",
            f"refs/tags/{short_name}",
            f"refs/tags/{short_name}^{{}}",
        ))
    expected_refs = set(patterns)
    attempts = []
    stdout = stderr = ""
    rc = 1
    rows = []
    absence_observations = []
    max_attempts = max(1, int(retry_attempts or 1))
    delays = tuple(retry_delays or ())
    for attempt_number in range(1, max_attempts + 1):
        attempt_timeout = _remaining_timeout(deadline, timeout)
        if attempt_timeout <= 0:
            rc = 1
            stderr = "the total remote resolution deadline was exhausted"
            attempts.append({
                "attempt": attempt_number,
                "stage": "targeted_ls_remote",
                "status": _DEADLINE_FAILURE,
                "reason": stderr,
                "retryable": False,
            })
            break
        stdout, stderr, rc = _git(
            repo_dir,
            "ls-remote",
            "--heads",
            "--tags",
            remote,
            *patterns,
            timeout=attempt_timeout,
        )
        if rc == 0:
            parsed_rows, malformed = _parse_remote_rows(stdout)
            unexpected_refs = sorted({
                ref for _commit, ref in parsed_rows if ref not in expected_refs
            })
            rows = [
                (commit, ref)
                for commit, ref in parsed_rows
                if ref in expected_refs
            ]
            if rows and not malformed:
                attempt_record = {
                    "attempt": attempt_number,
                    "stage": "targeted_ls_remote",
                    "status": "success",
                    "reason": "",
                    "retryable": False,
                }
                if unexpected_refs:
                    attempt_record["ignored_unexpected_refs"] = unexpected_refs
                attempts.append(attempt_record)
                break
            observation_status = (
                "remote_ref_observation_malformed"
                if malformed
                else (
                    "remote_ref_observation_unexpected"
                    if unexpected_refs
                    else "remote_ref_observation_empty"
                )
            )
            absence_observations.append({
                "status": observation_status,
                "signature": _empty_observation_signature(stdout),
            })
            attempts.append({
                "attempt": attempt_number,
                "stage": "targeted_ls_remote",
                "status": observation_status,
                "reason": (
                    "\n".join(malformed)
                    if malformed
                    else (
                        "remote returned only unexpected refs: "
                        + ", ".join(unexpected_refs)
                        if unexpected_refs
                        else "remote returned no matching ref"
                    )
                ),
                "retryable": attempt_number < max_attempts,
            })
            observation_failure = _absence_observation_failure(
                absence_observations,
            )
            if observation_failure is None:
                break
            if attempt_number >= max_attempts:
                rc = 1
                failure_type, stderr = observation_failure
                attempts[-1].update({
                    "status": failure_type,
                    "reason": stderr,
                    "retryable": False,
                })
                break
        else:
            reason = stderr or stdout or f"git ls-remote exited with {rc}"
            failure_type, retryable = classify_fetch_failure(reason, rc)
            attempts.append({
                "attempt": attempt_number,
                "stage": "targeted_ls_remote",
                "status": failure_type,
                "reason": reason,
                "retryable": retryable,
            })
            if not retryable or attempt_number >= max_attempts:
                break
        if not _sleep_before_retry(
            delays,
            attempt_number,
            deadline=deadline,
        ):
            rc = 1
            stderr = "the total remote resolution deadline was exhausted"
            attempts.append({
                "attempt": attempt_number,
                "stage": "targeted_ls_remote_retry_wait",
                "status": _DEADLINE_FAILURE,
                "reason": stderr,
                "retryable": False,
            })
            break

    queried_at = _now()
    if rc != 0:
        last = attempts[-1] if attempts else {}
        return {
            "queried_at": queried_at,
            "refs": [],
            "failures": [{
                "remote": remote,
                "stage": "targeted_ls_remote",
                "reason": str(last.get("reason") or stderr or stdout),
                "reason_code": str(last.get("status") or "fetch_failed"),
                "retryable": bool(last.get("retryable")),
                "attempts": attempts,
            }],
            "remotes": [remote],
            "query_mode": "targeted_exact",
        }

    peeled_tags = {
        ref[:-3]: commit
        for commit, ref in rows
        if ref.endswith("^{}")
    }
    candidates = []
    for commit, ref in rows:
        if ref.endswith("^{}"):
            continue
        if ref.startswith("refs/heads/"):
            kind = "branch"
            candidate_name = ref[len("refs/heads/"):]
        elif ref.startswith("refs/tags/"):
            kind = "tag"
            candidate_name = ref[len("refs/tags/"):]
            commit = peeled_tags.get(ref, commit)
        else:
            continue
        candidates.append({
            "remote": remote,
            "ref": f"{remote}/{candidate_name}",
            "canonical_ref": ref,
            "short_name": candidate_name,
            "kind": kind,
            "commit": commit,
            "score": 300,
        })
    candidates.sort(key=lambda item: (item["kind"] != "branch", item["ref"]))
    return {
        "queried_at": queried_at,
        "refs": candidates,
        "failures": [],
        "remotes": [remote],
        "query_mode": "targeted_exact",
        "attempts": attempts,
    }


def _compat_advertised_commit_inventory(
    repo_dir,
    remote,
    requested_commit,
    *,
    timeout=30,
    retry_attempts=DEFAULT_FETCH_ATTEMPTS,
    retry_delays=DEFAULT_FETCH_RETRY_DELAYS,
    deadline=None,
):
    """Compatibility fallback for servers that reject raw object fetches.

    This intentionally runs only after a targeted raw-SHA fetch was rejected.
    It checks advertised branch/tag tips on one remote and never performs the
    old eager all-remotes inventory before the targeted proof attempt.
    """
    remote = str(remote or "").strip()
    requested = str(requested_commit or "").strip().lower()
    attempts = []
    observations = []
    rows = []
    stderr = stdout = ""
    rc = 1
    max_attempts = max(1, int(retry_attempts or 1))
    delays = tuple(retry_delays or ())
    for attempt_number in range(1, max_attempts + 1):
        attempt_timeout = _remaining_timeout(deadline, timeout)
        if attempt_timeout <= 0:
            rc = 1
            stderr = "the total remote resolution deadline was exhausted"
            attempts.append({
                "attempt": attempt_number,
                "stage": "compat_advertised_ls_remote",
                "status": _DEADLINE_FAILURE,
                "reason": stderr,
                "retryable": False,
            })
            break
        stdout, stderr, rc = _git(
            repo_dir,
            "ls-remote",
            "--heads",
            "--tags",
            remote,
            timeout=attempt_timeout,
        )
        if rc == 0:
            rows, malformed = _parse_remote_rows(stdout)
            if rows and not malformed:
                attempts.append({
                    "attempt": attempt_number,
                    "stage": "compat_advertised_ls_remote",
                    "status": "success",
                    "reason": "",
                    "retryable": False,
                })
                break
            status = (
                "remote_ref_observation_malformed"
                if malformed
                else "remote_ref_observation_empty"
            )
            observations.append({
                "status": status,
                "signature": _empty_observation_signature(stdout),
            })
            attempts.append({
                "attempt": attempt_number,
                "stage": "compat_advertised_ls_remote",
                "status": status,
                "reason": "\n".join(malformed) if malformed else "remote returned no refs",
                "retryable": attempt_number < max_attempts,
            })
            observation_failure = _absence_observation_failure(observations)
            if observation_failure is None:
                break
            if attempt_number >= max_attempts:
                rc = 1
                failure_type, stderr = observation_failure
                attempts[-1].update({
                    "status": failure_type,
                    "reason": stderr,
                    "retryable": False,
                })
                break
        else:
            reason = stderr or stdout or f"git ls-remote exited with {rc}"
            failure_type, retryable = classify_fetch_failure(reason, rc)
            attempts.append({
                "attempt": attempt_number,
                "stage": "compat_advertised_ls_remote",
                "status": failure_type,
                "reason": reason,
                "retryable": retryable,
            })
            if not retryable or attempt_number >= max_attempts:
                break
        if not _sleep_before_retry(delays, attempt_number, deadline=deadline):
            rc = 1
            stderr = "the total remote resolution deadline was exhausted"
            attempts.append({
                "attempt": attempt_number,
                "stage": "compat_advertised_ls_remote_retry_wait",
                "status": _DEADLINE_FAILURE,
                "reason": stderr,
                "retryable": False,
            })
            break

    queried_at = _now()
    if rc != 0:
        last = attempts[-1] if attempts else {}
        return {
            "queried_at": queried_at,
            "refs": [],
            "failures": [{
                "remote": remote,
                "stage": "compat_advertised_ls_remote",
                "reason": str(last.get("reason") or stderr or stdout),
                "reason_code": str(last.get("status") or "fetch_failed"),
                "retryable": bool(last.get("retryable")),
                "attempts": attempts,
            }],
            "remotes": [remote],
            "query_mode": "compat_advertised_commit",
        }

    peeled_tags = {ref[:-3]: commit for commit, ref in rows if ref.endswith("^{}")}
    candidates = []
    for commit, canonical_ref in rows:
        if canonical_ref.endswith("^{}"):
            continue
        if canonical_ref.startswith("refs/heads/"):
            kind = "branch"
            short_name = canonical_ref[len("refs/heads/"):]
        elif canonical_ref.startswith("refs/tags/"):
            kind = "tag"
            short_name = canonical_ref[len("refs/tags/"):]
            commit = peeled_tags.get(canonical_ref, commit)
        else:
            continue
        if not str(commit).lower().startswith(requested):
            continue
        candidates.append({
            "remote": remote,
            "ref": f"{remote}/{short_name}",
            "canonical_ref": canonical_ref,
            "short_name": short_name,
            "kind": kind,
            "commit": commit,
            "score": 300,
        })
    return {
        "queried_at": queried_at,
        "refs": candidates,
        "failures": [],
        "remotes": [remote],
        "query_mode": "compat_advertised_commit",
        "attempts": attempts,
    }


def _requested_remote_targets(remote_names, requested_ref):
    names = list(remote_names or [])
    requested = str(requested_ref or "").strip()
    canonical_ref = ""
    short_name = requested
    if requested.startswith("refs/heads/"):
        canonical_ref = requested
        short_name = requested[len("refs/heads/"):]
    elif requested.startswith("refs/tags/"):
        canonical_ref = requested
        short_name = requested[len("refs/tags/"):]

    explicit_remote = ""
    if not canonical_ref and "/" in requested:
        prefix, remainder = requested.split("/", 1)
        if prefix in set(names):
            explicit_remote = prefix
            short_name = remainder
    if explicit_remote:
        return [explicit_remote], short_name, canonical_ref
    ordered = sorted(set(names), key=lambda name: (name != "origin", name))
    return ordered, short_name, canonical_ref


def _requested_remote_tiers(remote_names, requested_ref):
    """Return precedence tiers without imposing precedence within a peer tier."""
    targets, short_name, canonical_ref = _requested_remote_targets(
        remote_names,
        requested_ref,
    )
    requested = str(requested_ref or "").strip()
    explicit = False
    if not canonical_ref and "/" in requested:
        prefix, _remainder = requested.split("/", 1)
        explicit = prefix in set(remote_names or [])
    if explicit:
        return [targets], short_name, canonical_ref
    if "origin" in targets:
        peers = [name for name in targets if name != "origin"]
        return [["origin"], peers] if peers else [["origin"]], short_name, canonical_ref
    return [targets], short_name, canonical_ref


def _candidate_sort_key(candidate):
    return (
        str((candidate or {}).get("remote") or "") != "origin",
        str((candidate or {}).get("remote") or ""),
        str((candidate or {}).get("kind") or "") != "branch",
        str((candidate or {}).get("canonical_ref") or ""),
        str((candidate or {}).get("ref") or ""),
    )


def _group_remote_candidates(candidates):
    """Deduplicate remote aliases by immutable commit, preserving fallbacks."""
    grouped = {}
    for candidate in sorted((dict(item) for item in candidates or []), key=_candidate_sort_key):
        commit = str(candidate.get("commit") or "").strip().lower()
        if not commit:
            continue
        grouped.setdefault(commit, []).append(candidate)
    groups = []
    for commit, aliases in grouped.items():
        representative = dict(aliases[0])
        if len(aliases) > 1:
            representative["aliases"] = [
                {
                    "remote": str(item.get("remote") or ""),
                    "ref": str(item.get("ref") or ""),
                    "canonical_ref": str(item.get("canonical_ref") or ""),
                }
                for item in aliases
            ]
        groups.append((commit, representative, aliases))
    groups.sort(key=lambda item: _candidate_sort_key(item[1]))
    return groups


def _materialize_targeted_commit(
    repo_dir,
    candidate,
    commit,
    *,
    timeout=60,
    pinned=False,
    retry_attempts=DEFAULT_FETCH_ATTEMPTS,
    retry_delays=DEFAULT_FETCH_RETRY_DELAYS,
    deadline=None,
):
    """Materialize a selected SHA via its canonical ref, then exact SHA."""
    expected = str(commit or "").strip()
    fixed = _verify_commit_object(repo_dir, expected, deadline=deadline)
    attempts = []
    if fixed:
        attempts.append({
            "attempt": 0,
            "stage": "verify_local_commit",
            "status": "success",
            "reason": "",
            "retryable": False,
        })
        return {
            "status": "remote_source_resolved",
            "resolved_commit": fixed,
            "expected_commit": expected,
            "attempts": attempts,
            "resolution_mode": (
                "pinned_commit" if pinned else "live_remote"
            ),
        }

    max_attempts = max(1, int(retry_attempts or 1))
    delays = tuple(retry_delays or ())
    last_failure = {}
    remote = str((candidate or {}).get("remote") or "").strip()
    canonical_ref = str((candidate or {}).get("canonical_ref") or "").strip()

    # A canonical ref is the most broadly supported fetch target. It is safe to
    # fetch without a destination ref, then verify the immutable expected SHA.
    # If the ref moved or the server cannot serve it, fall back to the pinned SHA.
    if remote and canonical_ref:
        for attempt_number in range(1, max_attempts + 1):
            attempt_timeout = _remaining_timeout(deadline, timeout)
            if attempt_timeout <= 0:
                last_failure = {
                    "failure_type": _DEADLINE_FAILURE,
                    "reason": "the total remote resolution deadline was exhausted",
                    "retryable": False,
                }
                attempts.append({
                    "attempt": attempt_number,
                    "stage": "fetch_canonical_ref",
                    "status": _DEADLINE_FAILURE,
                    "reason": last_failure["reason"],
                    "retryable": False,
                    "target": canonical_ref,
                })
                break
            stdout, stderr, rc = _git(
                repo_dir,
                "fetch",
                "--no-tags",
                "--no-write-fetch-head",
                remote,
                canonical_ref,
                timeout=attempt_timeout,
            )
            if rc == 0:
                fixed = _verify_commit_object(
                    repo_dir,
                    expected,
                    deadline=deadline,
                )
                if fixed:
                    attempts.append({
                        "attempt": attempt_number,
                        "stage": "fetch_canonical_ref",
                        "status": "success",
                        "reason": "",
                        "retryable": False,
                        "target": canonical_ref,
                    })
                    return {
                        "status": "remote_source_resolved",
                        "resolved_commit": fixed,
                        "expected_commit": expected,
                        "attempts": attempts,
                        "resolution_mode": (
                            "pinned_commit" if pinned else "live_remote"
                        ),
                    }
                last_failure = {
                    "failure_type": "commit_verification_failed",
                    "reason": "canonical ref fetch did not materialize the selected commit",
                    "retryable": False,
                }
                attempts.append({
                    "attempt": attempt_number,
                    "stage": "fetch_canonical_ref",
                    "status": last_failure["failure_type"],
                    "reason": last_failure["reason"],
                    "retryable": False,
                    "target": canonical_ref,
                })
                break
            reason = stderr or stdout or f"git fetch exited with {rc}"
            failure_type, retryable = classify_fetch_failure(reason, rc)
            last_failure = {
                "failure_type": failure_type,
                "reason": reason,
                "retryable": retryable,
            }
            attempts.append({
                "attempt": attempt_number,
                "stage": "fetch_canonical_ref",
                "status": failure_type,
                "reason": reason,
                "retryable": retryable,
                "target": canonical_ref,
            })
            if not retryable or attempt_number >= max_attempts:
                break
            if not _sleep_before_retry(
                delays,
                attempt_number,
                deadline=deadline,
            ):
                last_failure = {
                    "failure_type": _DEADLINE_FAILURE,
                    "reason": "the total remote resolution deadline was exhausted",
                    "retryable": False,
                }
                break

    should_try_exact_sha = (
        not last_failure
        or str(last_failure.get("failure_type") or "") != "authentication_failed"
    )
    for attempt_number in (
        range(1, max_attempts + 1) if should_try_exact_sha else ()
    ):
        attempt_timeout = _remaining_timeout(deadline, timeout)
        if attempt_timeout <= 0:
            last_failure = {
                "failure_type": _DEADLINE_FAILURE,
                "reason": "the total remote resolution deadline was exhausted",
                "retryable": False,
            }
            attempts.append({
                "attempt": attempt_number,
                "stage": "fetch_commit",
                "status": _DEADLINE_FAILURE,
                "reason": last_failure["reason"],
                "retryable": False,
                "target": expected,
            })
            break
        fetched = _fetch_expected_commit(
            repo_dir,
            candidate,
            expected,
            timeout=attempt_timeout,
        )
        last_failure = fetched
        attempts.append({
            "attempt": attempt_number,
            "stage": "fetch_commit",
            "status": (
                "success"
                if fetched.get("status") == "success"
                else str(fetched.get("failure_type") or "fetch_failed")
            ),
            "reason": str(fetched.get("reason") or ""),
            "retryable": bool(fetched.get("retryable")),
            "target": expected,
        })
        if fetched.get("status") == "success":
            fixed = _verify_commit_object(
                repo_dir,
                expected,
                deadline=deadline,
            )
            if fixed:
                return {
                    "status": "remote_source_resolved",
                    "resolved_commit": fixed,
                    "expected_commit": expected,
                    "attempts": attempts,
                    "resolution_mode": (
                        "pinned_commit" if pinned else "live_remote"
                    ),
                }
            last_failure = {
                "failure_type": "commit_verification_failed",
                "reason": "fetched object is not the selected commit",
                "retryable": False,
            }
            attempts[-1].update({
                "status": "commit_verification_failed",
                "reason": last_failure["reason"],
                "retryable": False,
            })
            break
        if not fetched.get("retryable") or attempt_number >= max_attempts:
            break
        if not _sleep_before_retry(
            delays,
            attempt_number,
            deadline=deadline,
        ):
            last_failure = {
                "failure_type": _DEADLINE_FAILURE,
                "reason": "the total remote resolution deadline was exhausted",
                "retryable": False,
            }
            break

    failure_type = str(last_failure.get("failure_type") or "fetch_failed")
    status = (
        "remote_expected_commit_unmaterializable"
        if pinned
        else "remote_fetch_failed"
    )
    return {
        "status": status,
        "resolved_commit": "",
        "expected_commit": expected,
        "attempts": attempts,
        "failure": {
            "remote": str((candidate or {}).get("remote") or ""),
            "stage": str((attempts[-1] if attempts else {}).get("stage") or "fetch_commit"),
            "reason": str(last_failure.get("reason") or "remote fetch failed"),
            "reason_code": failure_type,
            "retryable": bool(last_failure.get("retryable")),
        },
    }


def _materialize_explicit_commit_from_remote(
    repo_dir,
    remote,
    commit,
    *,
    timeout=60,
    retry_attempts=DEFAULT_FETCH_ATTEMPTS,
    retry_delays=DEFAULT_FETCH_RETRY_DELAYS,
    deadline=None,
):
    """Prove an explicit SHA is fetchable before assigning remote provenance."""
    candidate = {
        "remote": str(remote or "").strip(),
        "ref": str(commit or "").strip(),
        "canonical_ref": "",
        "short_name": str(commit or "").strip(),
        "kind": "commit",
        "commit": str(commit or "").strip(),
        "score": 300,
    }
    attempts = []
    delays = tuple(retry_delays or ())
    max_attempts = max(1, int(retry_attempts or 1))
    last_failure = {}
    for attempt_number in range(1, max_attempts + 1):
        attempt_timeout = _remaining_timeout(deadline, timeout)
        if attempt_timeout <= 0:
            last_failure = {
                "failure_type": _DEADLINE_FAILURE,
                "reason": "the total remote resolution deadline was exhausted",
                "retryable": False,
            }
            attempts.append({
                "attempt": attempt_number,
                "stage": "fetch_explicit_commit",
                "status": _DEADLINE_FAILURE,
                "reason": last_failure["reason"],
                "retryable": False,
                "target": candidate["commit"],
            })
            break
        fetched = _fetch_expected_commit(
            repo_dir,
            candidate,
            candidate["commit"],
            timeout=attempt_timeout,
        )
        last_failure = dict(fetched)
        attempts.append({
            "attempt": attempt_number,
            "stage": "fetch_explicit_commit",
            "status": (
                "success"
                if fetched.get("status") == "success"
                else str(fetched.get("failure_type") or "fetch_failed")
            ),
            "reason": str(fetched.get("reason") or ""),
            "retryable": bool(fetched.get("retryable")),
            "target": candidate["commit"],
        })
        if fetched.get("status") == "success":
            fixed = _verify_commit_object(
                repo_dir,
                candidate["commit"],
                deadline=deadline,
            )
            if fixed:
                return {
                    "status": "remote_source_resolved",
                    "resolved_commit": fixed,
                    "expected_commit": fixed,
                    "attempts": attempts,
                    "resolution_mode": "explicit_remote_commit",
                    "candidate": candidate,
                }
            last_failure = {
                "failure_type": "commit_verification_failed",
                "reason": "remote accepted the explicit commit but it is unavailable locally",
                "retryable": False,
            }
            attempts[-1].update({
                "status": last_failure["failure_type"],
                "reason": last_failure["reason"],
                "retryable": False,
            })
            break
        if not fetched.get("retryable") or attempt_number >= max_attempts:
            break
        if not _sleep_before_retry(
            delays,
            attempt_number,
            deadline=deadline,
        ):
            last_failure = {
                "failure_type": _DEADLINE_FAILURE,
                "reason": "the total remote resolution deadline was exhausted",
                "retryable": False,
            }
            break
    return {
        "status": "remote_expected_commit_unmaterializable",
        "resolved_commit": "",
        "expected_commit": candidate["commit"],
        "attempts": attempts,
        "candidate": candidate,
        "failure": {
            "remote": candidate["remote"],
            "stage": "fetch_explicit_commit",
            "reason": str(last_failure.get("reason") or "explicit commit could not be fetched"),
            "reason_code": str(last_failure.get("failure_type") or "fetch_failed"),
            "retryable": bool(last_failure.get("retryable")),
        },
    }


def _resolve_pinned_selected_ref(
    repo_dir,
    requested_ref,
    expected_commit,
    remote_names,
    *,
    expected_remote="",
    expected_remote_ref="",
    query_timeout=30,
    fetch_timeout=60,
    deadline=None,
):
    """Observe a selected ref, but materialize its previously pinned SHA.

    A live ref observation is diagnostic only once a prior selection has fixed
    an immutable commit. Ref movement must not silently replace that commit or
    turn into a movement blocker; canonical-ref transfer and exact-SHA fetch
    both continue to target the pinned object on the selected remote tier.
    """
    repository_path = str(Path(repo_dir).resolve())
    requested_text = str(requested_ref or "").strip()
    expected = str(expected_commit or "").strip()
    expected_remote = str(expected_remote or "").strip()
    expected_remote_ref = str(expected_remote_ref or "").strip()
    remote_tiers, short_name, canonical_ref = _requested_remote_tiers(
        remote_names,
        requested_text,
    )
    if expected_remote_ref:
        canonical_ref = expected_remote_ref
        if canonical_ref.startswith("refs/heads/"):
            short_name = canonical_ref[len("refs/heads/"):]
        elif canonical_ref.startswith("refs/tags/"):
            short_name = canonical_ref[len("refs/tags/"):]
        else:
            short_name = canonical_ref
    if expected_remote:
        selected_remotes = [expected_remote] if expected_remote in set(remote_names) else []
    else:
        selected_remotes = list(remote_tiers[0] if remote_tiers else [])
    if not selected_remotes:
        result = _base_result(
            "remote_expected_commit_unmaterializable",
            requested_ref,
            [],
            [{
                "remote": expected_remote,
                "stage": "select_remote",
                "reason": "the remote tier selected for the pinned ref is not configured",
                "reason_code": "expected_remote_not_configured",
                "repository_path": repository_path,
            }],
        )
        result.update({
            "expected_commit": expected,
            "observed_commit": "",
            "repository_path": repository_path,
            "configured_remotes": list(remote_names),
            "query_mode": "pinned_targeted_exact",
        })
        return result

    observation_failures = []
    observation_attempts = []
    materialization_candidates = []
    observed_commits = []
    queried_at = ""
    for remote in selected_remotes:
        inventory = _targeted_remote_ref_inventory(
            repo_dir,
            remote,
            short_name,
            canonical_ref=canonical_ref,
            timeout=query_timeout,
            deadline=deadline,
        )
        queried_at = str(inventory.get("queried_at") or queried_at)
        observation_attempts.append({
            "remote": remote,
            "attempts": list(inventory.get("attempts") or []),
        })
        observation_failures.extend(
            {**failure, "repository_path": repository_path}
            for failure in inventory.get("failures") or []
        )
        live_candidates = [dict(item) for item in inventory.get("refs") or []]
        for live_candidate in live_candidates:
            observed = str(live_candidate.get("commit") or "").strip()
            if observed:
                observed_commits.append(observed)
            materialization_candidates.append({
                **live_candidate,
                "commit": expected,
                "observed_commit": observed,
            })
        if live_candidates:
            continue
        synthetic_ref = (
            requested_text
            if requested_text.startswith(f"{remote}/")
            else f"{remote}/{short_name}"
        )
        materialization_candidates.append({
            "remote": remote,
            "ref": synthetic_ref,
            "canonical_ref": canonical_ref,
            "short_name": short_name,
            "kind": "tag" if canonical_ref.startswith("refs/tags/") else "branch",
            "commit": expected,
            "observed_commit": "",
            "score": 300,
        })

    materialization_failures = []
    last_materialized = {}
    for candidate in materialization_candidates:
        last_materialized = _materialize_targeted_commit(
            repo_dir,
            candidate,
            expected,
            timeout=fetch_timeout,
            pinned=True,
            deadline=deadline,
        )
        fixed_commit = str(last_materialized.get("resolved_commit") or "")
        if fixed_commit:
            result = _base_result(
                "remote_source_resolved",
                requested_ref,
                [candidate],
                queried_at=queried_at,
            )
            result.update({
                "resolved_ref": str(candidate.get("ref") or requested_text),
                "resolved_commit": fixed_commit,
                "remote": str(candidate.get("remote") or ""),
                "remote_ref": str(candidate.get("canonical_ref") or ""),
                "resolution_mode": "pinned_commit",
                "expected_commit": expected,
                "observed_commit": str(candidate.get("observed_commit") or ""),
                "observed_live_commits": sorted(set(observed_commits)),
                "attempts": list(last_materialized.get("attempts") or []),
                "observation_attempts": observation_attempts,
                "observation_failures": observation_failures,
                "repository_path": repository_path,
                "configured_remotes": list(remote_names),
                "query_mode": "pinned_targeted_exact",
                "selected_remote_tier": 0,
            })
            return result
        failure = dict(last_materialized.get("failure") or {})
        materialization_failures.append({
            "remote": str(candidate.get("remote") or ""),
            "stage": str(failure.get("stage") or "fetch_commit"),
            "reason": str(failure.get("reason") or "pinned commit could not be fetched"),
            "reason_code": str(failure.get("reason_code") or "fetch_failed"),
            "attempts": list(last_materialized.get("attempts") or []),
            "repository_path": repository_path,
        })

    observed_commit = (
        observed_commits[0]
        if len(set(observed_commits)) == 1
        else ""
    )
    result = _base_result(
        "remote_expected_commit_unmaterializable",
        requested_ref,
        materialization_candidates,
        [*materialization_failures, *observation_failures],
        queried_at,
    )
    result.update({
        "expected_commit": expected,
        "observed_commit": observed_commit,
        "observed_live_commits": sorted(set(observed_commits)),
        "attempts": list(last_materialized.get("attempts") or []),
        "observation_attempts": observation_attempts,
        "repository_path": repository_path,
        "configured_remotes": list(remote_names),
        "query_mode": "pinned_targeted_exact",
        "selected_remote_tier": 0,
    })
    return result


def resolve_remote_source_ref(
    repo_dir,
    requested_ref,
    query_timeout=30,
    fetch_timeout=60,
    *,
    expected_commit="",
    expected_remote="",
    expected_remote_ref="",
):
    """Resolve exactly one requested remote ref and pin it to a commit SHA."""
    deadline = _new_deadline(query_timeout, fetch_timeout)
    requested_text = str(requested_ref or "").strip()
    expected_commit = str(expected_commit or "").strip()
    expected_remote = str(expected_remote or "").strip()
    expected_remote_ref = str(expected_remote_ref or "").strip()
    if expected_commit and expected_remote and expected_remote_ref:
        short_name = (
            expected_remote_ref[len("refs/heads/"):]
            if expected_remote_ref.startswith("refs/heads/")
            else (
                expected_remote_ref[len("refs/tags/"):]
                if expected_remote_ref.startswith("refs/tags/")
                else expected_remote_ref
            )
        )
        bound_candidate = {
            "remote": expected_remote,
            "ref": f"{expected_remote}/{short_name}",
            "canonical_ref": expected_remote_ref,
            "short_name": short_name,
            "kind": "tag" if expected_remote_ref.startswith("refs/tags/") else "branch",
            "commit": expected_commit,
            "score": 300,
        }
        materialized = _materialize_targeted_commit(
            repo_dir,
            bound_candidate,
            expected_commit,
            timeout=fetch_timeout,
            pinned=True,
            deadline=deadline,
        )
        if not materialized.get("resolved_commit"):
            failure = dict(materialized.get("failure") or {})
            result = _base_result(
                str(materialized.get("status") or "remote_expected_commit_unmaterializable"),
                requested_ref,
                [bound_candidate],
                [{
                    "remote": expected_remote,
                    "stage": str(failure.get("stage") or "fetch_commit"),
                    "reason": str(failure.get("reason") or "pinned commit could not be fetched"),
                    "reason_code": str(failure.get("reason_code") or "fetch_failed"),
                    "attempts": list(materialized.get("attempts") or []),
                }],
            )
            result.update({
                "expected_commit": expected_commit,
                "attempts": list(materialized.get("attempts") or []),
                "repository_path": str(Path(repo_dir).resolve()),
                "query_mode": "pinned_commit",
            })
            return result
        result = _base_result(
            "remote_source_resolved",
            requested_ref,
            [bound_candidate],
        )
        result.update({
            "resolved_ref": bound_candidate["ref"],
            "resolved_commit": materialized["resolved_commit"],
            "remote": expected_remote,
            "remote_ref": expected_remote_ref,
            "resolution_mode": str(materialized.get("resolution_mode") or "pinned_commit"),
            "expected_commit": expected_commit,
            "attempts": list(materialized.get("attempts") or []),
            "repository_path": str(Path(repo_dir).resolve()),
            "configured_remotes": [expected_remote],
            "query_mode": "pinned_commit",
        })
        return result

    remote_names, remote_failures = _remote_names(repo_dir, deadline=deadline)
    repository_path = str(Path(repo_dir).resolve())
    if remote_failures:
        failures = [
            {**failure, "repository_path": repository_path}
            for failure in remote_failures
        ]
        failure_codes = {
            str(item.get("reason_code") or "")
            for item in failures
        }
        status = (
            "repository_not_git"
            if "repository_not_git" in failure_codes
            else "remote_query_failed"
        )
        result = _base_result(status, requested_ref, [], failures)
        result.update({
            "repository_path": repository_path,
            "configured_remotes": [],
            "query_mode": "local_remote_discovery",
        })
        return result
    if not remote_names:
        result = _base_result("remote_configuration_missing", requested_ref, [], [{
            "remote": "",
            "stage": "select_remote",
            "reason": "repository has no configured remote",
            "reason_code": "remote_configuration_missing",
            "repository_path": repository_path,
            "configured_remotes": [],
        }])
        result.update({
            "repository_path": repository_path,
            "configured_remotes": [],
            "query_mode": "local_remote_selection",
        })
        return result

    # When a prior remote selection supplied an immutable SHA, a later live
    # observation can explain ref movement but cannot replace that authority.
    # This path lets downstream stages pass the selected ref plus its binding
    # directly, without having to reproduce remote/ref parsing themselves.
    if expected_commit and not _COMMIT_RE.fullmatch(requested_text):
        return _resolve_pinned_selected_ref(
            repo_dir,
            requested_ref,
            expected_commit,
            remote_names,
            expected_remote=expected_remote,
            expected_remote_ref=expected_remote_ref,
            query_timeout=query_timeout,
            fetch_timeout=fetch_timeout,
            deadline=deadline,
        )

    query_failures = []
    queried_at = ""
    candidate_groups = []

    if _COMMIT_RE.fullmatch(requested_text):
        tiers, _short_name, _canonical_ref = _requested_remote_tiers(
            remote_names,
            requested_text,
        )
        is_full_commit = bool(_FULL_OBJECT_RE.fullmatch(requested_text))
        all_failures = []
        last_expected = requested_text
        for tier_index, tier in enumerate(tiers):
            tier_failures = []
            raw_successes = []

            # Full object IDs are first proven with an exact remote fetch. This
            # is both cheaper and stronger than enumerating every advertised ref.
            if is_full_commit:
                for remote in tier:
                    materialized = _materialize_explicit_commit_from_remote(
                        repo_dir,
                        remote,
                        requested_text,
                        timeout=fetch_timeout,
                        deadline=deadline,
                    )
                    candidate = dict(materialized.get("candidate") or {})
                    if materialized.get("resolved_commit"):
                        raw_successes.append((candidate, materialized))
                        continue
                    failure = dict(materialized.get("failure") or {})
                    tier_failures.append({
                        "remote": remote,
                        "stage": "fetch_explicit_commit",
                        "reason": str(failure.get("reason") or "explicit commit could not be fetched"),
                        "reason_code": str(failure.get("reason_code") or "fetch_failed"),
                        "attempts": list(materialized.get("attempts") or []),
                        "repository_path": repository_path,
                    })
                if raw_successes:
                    raw_candidates = [item[0] for item in raw_successes]
                    grouped = _group_remote_candidates(raw_candidates)
                    representative = grouped[0][1] if grouped else raw_candidates[0]
                    selected, materialized = raw_successes[0]
                    result = _base_result(
                        "remote_source_resolved",
                        requested_ref,
                        [representative],
                        [*all_failures, *tier_failures],
                        queried_at,
                    )
                    result.update({
                        "resolved_ref": requested_text,
                        "resolved_commit": materialized["resolved_commit"],
                        "remote": selected.get("remote") or "",
                        "remote_ref": "",
                        "resolution_mode": "explicit_remote_commit",
                        "expected_commit": materialized["resolved_commit"],
                        "attempts": list(materialized.get("attempts") or []),
                        "repository_path": repository_path,
                        "configured_remotes": list(remote_names),
                        "query_mode": "explicit_commit_remote",
                        "query_strategy": "targeted_raw_commit",
                        "selected_remote_tier": tier_index,
                    })
                    return result

            # Short IDs require advertised full IDs to prove uniqueness. Full
            # IDs use this only as a compatibility fallback when the server
            # rejects raw object fetches.
            compat_candidates = []
            compat_failures = []
            compat_remotes = list(tier)
            if is_full_commit:
                compat_remotes = [
                    failure["remote"]
                    for failure in tier_failures
                    if failure.get("reason_code") in {
                        "remote_ref_not_found",
                        "commit_verification_failed",
                    }
                ]
            for remote in compat_remotes:
                inventory = _compat_advertised_commit_inventory(
                    repo_dir,
                    remote,
                    requested_text,
                    timeout=query_timeout,
                    deadline=deadline,
                )
                queried_at = str(inventory.get("queried_at") or queried_at)
                compat_candidates.extend(
                    dict(item) for item in inventory.get("refs") or []
                )
                compat_failures.extend(
                    {**failure, "repository_path": repository_path}
                    for failure in inventory.get("failures") or []
                )

            groups = _group_remote_candidates(compat_candidates)
            if len(groups) > 1:
                result = _base_result(
                    "remote_source_ambiguous",
                    requested_ref,
                    [group[1] for group in groups],
                    [*all_failures, *tier_failures, *compat_failures],
                    queried_at,
                )
                result.update({
                    "repository_path": repository_path,
                    "configured_remotes": list(remote_names),
                    "query_mode": "explicit_commit_remote",
                    "query_strategy": "compat_advertised_commit",
                    "selected_remote_tier": tier_index,
                })
                return result
            if groups:
                commit, representative, aliases = groups[0]
                last_expected = commit
                # A failed peer query can hide a different full object behind a
                # short ID, so short-SHA uniqueness is not established.
                if not is_full_commit and compat_failures:
                    result = _base_result(
                        "remote_query_failed",
                        requested_ref,
                        [representative],
                        [*all_failures, *tier_failures, *compat_failures],
                        queried_at,
                    )
                    result.update({
                        "repository_path": repository_path,
                        "configured_remotes": list(remote_names),
                        "query_mode": "explicit_commit_remote",
                        "query_strategy": "compat_advertised_commit",
                        "selection_blocked_by_peer_remote": True,
                    })
                    return result
                materialization_failures = []
                for selected in aliases:
                    materialized = _materialize_targeted_commit(
                        repo_dir,
                        selected,
                        commit,
                        timeout=fetch_timeout,
                        deadline=deadline,
                    )
                    if materialized.get("resolved_commit"):
                        result = _base_result(
                            "remote_source_resolved",
                            requested_ref,
                            [representative],
                            [*all_failures, *tier_failures, *compat_failures, *materialization_failures],
                            queried_at,
                        )
                        result.update({
                            "resolved_ref": selected.get("ref") or requested_text,
                            "resolved_commit": materialized["resolved_commit"],
                            "remote": selected.get("remote") or "",
                            "remote_ref": selected.get("canonical_ref") or "",
                            "resolution_mode": "explicit_remote_commit",
                            "expected_commit": commit,
                            "attempts": list(materialized.get("attempts") or []),
                            "repository_path": repository_path,
                            "configured_remotes": list(remote_names),
                            "query_mode": "explicit_commit_remote",
                            "query_strategy": "compat_advertised_commit",
                            "selected_remote_tier": tier_index,
                        })
                        return result
                    failure = dict(materialized.get("failure") or {})
                    materialization_failures.append({
                        "remote": selected.get("remote") or "",
                        "stage": str(failure.get("stage") or "fetch_commit"),
                        "reason": str(failure.get("reason") or "remote fetch failed"),
                        "reason_code": str(failure.get("reason_code") or "fetch_failed"),
                        "attempts": list(materialized.get("attempts") or []),
                        "repository_path": repository_path,
                    })
                tier_failures.extend(materialization_failures)

            hard_failures = [
                failure
                for failure in [*tier_failures, *compat_failures]
                if failure.get("reason_code") not in {
                    "remote_ref_not_found",
                    "commit_verification_failed",
                }
            ]
            all_failures.extend([*tier_failures, *compat_failures])
            if hard_failures and tier_index < len(tiers) - 1:
                result = _base_result(
                    "remote_query_failed",
                    requested_ref,
                    [],
                    all_failures,
                    queried_at,
                )
                result.update({
                    "expected_commit": last_expected,
                    "repository_path": repository_path,
                    "configured_remotes": list(remote_names),
                    "query_mode": "explicit_commit_remote",
                    "query_strategy": "targeted_raw_commit",
                    "selection_blocked_by_higher_priority_remote": True,
                })
                return result

        result = _base_result(
            "remote_expected_commit_unmaterializable",
            requested_ref,
            [],
            all_failures,
            queried_at,
        )
        result.update({
            "expected_commit": last_expected,
            "repository_path": repository_path,
            "configured_remotes": list(remote_names),
            "query_mode": "explicit_commit_remote",
            "query_strategy": "targeted_raw_commit",
        })
        return result

    remote_tiers, short_name, canonical_ref = _requested_remote_tiers(
        remote_names, requested_ref,
    )
    confirmed_absences = []
    selected_tier = None
    candidate_groups = []
    for tier_index, tier in enumerate(remote_tiers):
        tier_candidates = []
        tier_failures = []
        for remote in tier:
            inventory = _targeted_remote_ref_inventory(
                repo_dir,
                remote,
                short_name,
                canonical_ref=canonical_ref,
                timeout=query_timeout,
                deadline=deadline,
            )
            queried_at = str(inventory.get("queried_at") or queried_at)
            tier_candidates.extend(
                dict(item) for item in inventory.get("refs") or []
            )
            inventory_failures = list(inventory.get("failures") or [])
            tier_failures.extend(
                {**failure, "repository_path": repository_path}
                for failure in inventory_failures
            )
            if not inventory.get("refs") and not inventory_failures:
                confirmed_absences.append({
                    "remote": remote,
                    "stage": "targeted_ls_remote",
                    "reason": "requested branch or tag was consistently absent",
                    "reason_code": "remote_ref_not_found",
                    "attempts": list(inventory.get("attempts") or []),
                    "repository_path": repository_path,
                })
        if tier_failures:
            query_failures.extend(tier_failures)
            result = _base_result(
                "remote_query_failed",
                requested_ref,
                [group[1] for group in _group_remote_candidates(tier_candidates)],
                query_failures,
                queried_at,
            )
            result.update({
                "repository_path": repository_path,
                "configured_remotes": list(remote_names),
                "query_mode": "targeted_exact",
                "selection_blocked_by_higher_priority_remote": (
                    tier_index < len(remote_tiers) - 1
                ),
                "selection_blocked_by_peer_remote": bool(tier_candidates),
                "failed_remote_tier": tier_index,
            })
            return result
        candidate_groups = _group_remote_candidates(tier_candidates)
        if len(candidate_groups) > 1:
            result = _base_result(
                "remote_source_ambiguous",
                requested_ref,
                [group[1] for group in candidate_groups],
                query_failures,
                queried_at,
            )
            result.update({
                "repository_path": repository_path,
                "configured_remotes": list(remote_names),
                "query_mode": "targeted_exact",
                "selected_remote_tier": tier_index,
            })
            return result
        if candidate_groups:
            selected_tier = tier_index
            break

    if not candidate_groups:
        result = _base_result(
            "remote_ref_not_found",
            requested_ref,
            [],
            confirmed_absences,
            queried_at,
        )
        result.update({
            "repository_path": repository_path,
            "configured_remotes": list(remote_names),
            "query_mode": "targeted_exact",
        })
        return result

    _commit, representative, aliases = candidate_groups[0]

    materialization_failures = []
    materialized = {}
    selected = aliases[0]
    for selected in aliases:
        materialized = _materialize_targeted_commit(
            repo_dir,
            selected,
            selected.get("commit"),
            timeout=fetch_timeout,
            deadline=deadline,
        )
        if materialized.get("resolved_commit"):
            break
        failure = dict(materialized.get("failure") or {})
        materialization_failures.append({
            "remote": selected.get("remote") or "",
            "stage": str(failure.get("stage") or "fetch_commit"),
            "reason": str(failure.get("reason") or "remote fetch failed"),
            "reason_code": str(failure.get("reason_code") or materialized.get("status") or "fetch_failed"),
            "attempts": list(materialized.get("attempts") or []),
            "repository_path": repository_path,
        })

    fixed_commit = str(materialized.get("resolved_commit") or "")
    failures = [*query_failures, *materialization_failures]
    if not fixed_commit:
        result = _base_result(
            str(materialized.get("status") or "remote_fetch_failed"),
            requested_ref,
            [representative],
            failures,
            queried_at,
        )
        result.update({
            "expected_commit": str(materialized.get("expected_commit") or representative.get("commit") or ""),
            "attempts": list(materialized.get("attempts") or []),
            "repository_path": repository_path,
            "configured_remotes": list(remote_names),
            "query_mode": "targeted_exact",
        })
        return result

    result = _base_result(
        "remote_source_resolved",
        requested_ref,
        [representative],
        failures,
        queried_at,
    )
    result.update({
        "resolved_ref": selected["ref"],
        "resolved_commit": fixed_commit,
        "remote": selected["remote"],
        "remote_ref": selected["canonical_ref"],
        "resolution_mode": str(materialized.get("resolution_mode") or "live_remote"),
        "expected_commit": str(materialized.get("expected_commit") or fixed_commit),
        "attempts": list(materialized.get("attempts") or []),
        "repository_path": repository_path,
        "configured_remotes": list(remote_names),
        "query_mode": "targeted_exact",
        "selected_remote_tier": selected_tier,
    })
    return result


def _is_local_ref_absence(reason):
    text = str(reason or "").strip().lower()
    return any(pattern in text for pattern in _LOCAL_REF_ABSENT_PATTERNS)


def _verify_local_commit_details(repo_dir, requested_ref):
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
        stdout, stderr, rc = _git(
            repo_dir,
            "rev-parse",
            "--verify",
            f"{candidate}^{{commit}}",
            timeout=10,
        )
        if rc == 0 and stdout:
            return stdout.splitlines()[-1].strip(), None
        reason = str(stderr or stdout or f"git rev-parse exited with {rc}")
        if rc not in {1, 128} or not _is_local_ref_absence(reason):
            return "", {
                "stage": "local_ref_resolution",
                "reason": reason,
                "reason_code": "local_ref_resolution_failed",
                "return_code": rc,
            }
    return "", None


def resolve_local_source_ref(
    repo_dir,
    requested_ref,
    *,
    allow_local_source=False,
    allow_dirty_local_source=False,
):
    """Resolve a local ref only after explicit confirmation."""
    commit, ref_failure = _verify_local_commit_details(repo_dir, requested_ref)
    stdout, stderr, rc = _git(repo_dir, "status", "--porcelain", timeout=10)
    if rc != 0:
        reason = str(stderr or stdout or f"git status exited with {rc}")
        failures = [{
            "stage": "local_status",
            "reason": reason,
            "reason_code": "local_status_unavailable",
            "return_code": rc,
        }]
        result = _base_result(
            "local_status_unavailable",
            requested_ref,
            failures=failures,
        )
        result.update({
            "local_candidate_commit": commit,
            "dirty": None,
            "status_available": False,
        })
        return result
    dirty = bool(stdout.strip())
    if ref_failure:
        result = _base_result(
            "local_ref_resolution_failed",
            requested_ref,
            failures=[ref_failure],
        )
        result.update({
            "dirty": dirty,
            "status_available": True,
        })
        return result
    if not allow_local_source:
        result = _base_result("awaiting_local_source_confirmation", requested_ref)
        result.update({
            "local_candidate_commit": commit,
            "dirty": dirty,
            "status_available": True,
        })
        return result
    if not commit:
        failures = [{
            "stage": "local_resolve",
            "reason": "confirmed local ref was not found",
            "reason_code": "local_ref_not_found",
        }]
        result = _base_result(
            "remote_source_unavailable",
            requested_ref,
            failures=failures,
        )
        result.update({
            "dirty": dirty,
            "status_available": True,
        })
        return result
    if dirty and not allow_dirty_local_source:
        result = _base_result("awaiting_dirty_local_source_confirmation", requested_ref)
        result.update({
            "local_candidate_commit": commit,
            "dirty": True,
            "status_available": True,
        })
        return result
    result = _base_result("user_confirmed_local_source", requested_ref)
    result.update({
        "resolved_ref": str(requested_ref or "").strip(),
        "resolved_commit": commit,
        "resolution_mode": "user_confirmed_local_source",
        "dirty": dirty,
        "status_available": True,
    })
    return result


__all__ = [
    "classify_fetch_failure",
    "query_live_remote_refs",
    "materialize_remote_source_candidate",
    "resolve_local_source_ref",
    "resolve_remote_source_ref",
]

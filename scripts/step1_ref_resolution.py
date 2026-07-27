#!/usr/bin/env python3
"""Safe, read-only Git ref resolution for Step1 source snapshots."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from compat import git_cmd, run_cmd
from remote_source_refs import resolve_local_source_ref, resolve_remote_source_ref


_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
_CORE_VERSION_RE = re.compile(r"\d+(?:\.\d+)+")


def _git(repo_dir, *args, timeout=20):
    stdout, stderr, rc = run_cmd(
        git_cmd() + list(args),
        cwd=str(Path(repo_dir).resolve()),
        timeout=timeout,
    )
    return str(stdout or "").strip(), str(stderr or "").strip(), rc


def _verify_commit(repo_dir, ref):
    stdout, _stderr, rc = _git(repo_dir, "rev-parse", "--verify", f"{ref}^{{commit}}", timeout=10)
    if rc != 0 or not stdout:
        return ""
    return stdout.splitlines()[-1].strip()


def _exact_ref_target(repo_dir, requested_ref):
    requested_ref = str(requested_ref or "").strip()
    if not requested_ref:
        return "", ""
    candidates = []
    if requested_ref.startswith("refs/"):
        candidates.append(requested_ref)
    else:
        candidates.extend((
            f"refs/heads/{requested_ref}",
            f"refs/tags/{requested_ref}",
        ))
        if "/" in requested_ref:
            candidates.append(f"refs/remotes/{requested_ref}")
    for canonical_ref in candidates:
        commit = _verify_commit(repo_dir, canonical_ref)
        if commit:
            if canonical_ref.startswith("refs/heads/"):
                display_ref = canonical_ref[len("refs/heads/"):]
            elif canonical_ref.startswith("refs/remotes/"):
                display_ref = canonical_ref[len("refs/remotes/"):]
            elif canonical_ref.startswith("refs/tags/"):
                display_ref = canonical_ref[len("refs/tags/"):]
            else:
                display_ref = canonical_ref
            return display_ref, commit
    if requested_ref == "HEAD" or _COMMIT_RE.fullmatch(requested_ref):
        commit = _verify_commit(repo_dir, requested_ref)
        if commit:
            return requested_ref, commit
    return "", ""


def _list_branch_refs(repo_dir):
    stdout, _stderr, rc = _git(
        repo_dir,
        "for-each-ref",
        "--format=%(refname)%09%(objectname)",
        "refs/heads",
        "refs/remotes",
    )
    if rc != 0:
        return []
    refs = []
    for raw_line in stdout.splitlines():
        parts = raw_line.split("\t", 1)
        if len(parts) != 2:
            continue
        canonical_ref, commit = (part.strip() for part in parts)
        if not canonical_ref or not commit or canonical_ref.endswith("/HEAD"):
            continue
        if canonical_ref.startswith("refs/heads/"):
            kind = "local"
            display_ref = canonical_ref[len("refs/heads/"):]
            short_name = display_ref
        elif canonical_ref.startswith("refs/remotes/"):
            kind = "remote"
            display_ref = canonical_ref[len("refs/remotes/"):]
            short_name = display_ref.split("/", 1)[1] if "/" in display_ref else display_ref
        else:
            continue
        refs.append({
            "ref": display_ref,
            "canonical_ref": canonical_ref,
            "short_name": short_name,
            "kind": kind,
            "commit": commit,
        })
    return refs


def _version_boundary_score(candidate_name, requested_ref):
    requested = re.sub(r"(?i)-SNAPSHOT$", "", str(requested_ref or "").strip())
    version_match = _CORE_VERSION_RE.search(requested)
    if not version_match:
        return 0
    version = version_match.group(0).lower()
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
        if following and following not in "-_/":
            continue
        return 120


def _candidate_score(candidate, requested_ref):
    requested = str(requested_ref or "").strip()
    if not requested:
        return 0
    if candidate["ref"] == requested:
        return 220
    if candidate["short_name"] == requested:
        return 200
    return _version_boundary_score(candidate["short_name"], requested)


def _matching_candidates(repo_dir, requested_ref):
    scored = []
    for candidate in _list_branch_refs(repo_dir):
        score = _candidate_score(candidate, requested_ref)
        if score:
            scored.append({**candidate, "score": score})
    if not scored:
        return []
    highest_score = max(item["score"] for item in scored)
    return sorted(
        (item for item in scored if item["score"] == highest_score),
        key=lambda item: (0 if item["kind"] == "local" else 1, item["ref"]),
    )


def _fingerprint(requested_ref, candidates):
    payload = {
        "requested_ref": str(requested_ref or "").strip(),
        "candidates": [
            {
                "ref": item.get("ref", ""),
                "commit": item.get("commit", ""),
                "kind": item.get("kind", ""),
                "score": item.get("score", 0),
            }
            for item in candidates or []
        ],
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def resolve_step1_ref(
    repo_dir,
    requested_ref,
    *,
    expected_commit="",
    expected_remote="",
    expected_remote_ref="",
    allow_local_source=False,
    allow_dirty_local_source=False,
):
    """Resolve Step1 auxiliary source from live remotes, with confirmed local fallback."""
    remote_kwargs = {"expected_commit": expected_commit}
    if expected_remote:
        remote_kwargs["expected_remote"] = expected_remote
    if expected_remote_ref:
        remote_kwargs["expected_remote_ref"] = expected_remote_ref
    remote = resolve_remote_source_ref(repo_dir, requested_ref, **remote_kwargs)
    if remote.get("status") == "remote_source_resolved":
        return {**remote, "status": "resolved", "source_status": "remote_source_resolved"}
    if remote.get("status") == "remote_source_ambiguous":
        return {**remote, "status": "ambiguous", "source_status": "remote_source_ambiguous"}
    if remote.get("status") == "remote_ref_moved":
        # Backward-compatible containment for callers or persisted fixtures
        # that still surface the retired status.  A moving ref cannot revoke
        # the immutable expected commit and is never a user selection problem.
        return {
            **remote,
            "status": "fetch_failed",
            "source_status": "remote_expected_commit_unmaterializable",
            "legacy_source_status": "remote_ref_moved",
        }
    remote_operational_failure = remote.get("status") in {
        "remote_fetch_failed",
        "remote_query_failed",
        "remote_expected_commit_unmaterializable",
    }
    if remote_operational_failure and not allow_local_source:
        return {
            **remote,
            "status": "fetch_failed",
            "source_status": str(remote.get("status") or "remote_fetch_failed"),
        }

    local = resolve_local_source_ref(
        repo_dir,
        requested_ref,
        allow_local_source=allow_local_source,
        allow_dirty_local_source=allow_dirty_local_source,
    )
    if local.get("status") == "user_confirmed_local_source":
        return {
            **local,
            "status": "resolved",
            "source_status": "user_confirmed_local_source",
            "remote_failures": list(remote.get("failures") or []),
        }
    status = (
        "dirty_confirmation_required"
        if local.get("status") == "awaiting_dirty_local_source_confirmation"
        else ("fetch_failed" if remote_operational_failure else "not_found")
    )
    return {
        **remote,
        "status": status,
        "source_status": (
            str(remote.get("status") or "remote_fetch_failed")
            if remote_operational_failure
            else str(local.get("status") or "awaiting_local_source_confirmation")
        ),
        "local_candidate_commit": str(local.get("local_candidate_commit") or ""),
        "dirty": bool(local.get("dirty")),
    }


__all__ = ["resolve_step1_ref"]

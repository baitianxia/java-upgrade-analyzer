#!/usr/bin/env python3
"""Safe, read-only Git ref resolution for Step1 source snapshots."""

from __future__ import annotations

from remote_source_refs import resolve_local_source_ref, resolve_remote_source_ref


_LOCAL_GIT_OPERATIONAL_FAILURES = {
    "local_status_unavailable",
    "local_ref_resolution_failed",
}


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
    if str(requested_ref or "").strip() == "HEAD" and not allow_local_source:
        local = resolve_local_source_ref(
            repo_dir,
            requested_ref,
            allow_local_source=False,
            allow_dirty_local_source=allow_dirty_local_source,
        )
        if local.get("status") in _LOCAL_GIT_OPERATIONAL_FAILURES:
            return {
                **local,
                "status": "fetch_failed",
                "source_status": str(local.get("status")),
            }
        return {
            **local,
            "status": (
                "dirty_confirmation_required"
                if local.get("status")
                == "awaiting_dirty_local_source_confirmation"
                else "not_found"
            ),
            "source_status": str(
                local.get("status")
                or "awaiting_local_source_confirmation"
            ),
        }
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

    if not allow_local_source:
        return {
            **remote,
            "status": "not_found",
            "source_status": str(
                remote.get("status") or "remote_ref_not_found"
            ),
            "remote_source_status": str(remote.get("status") or ""),
            "local_candidate_commit": "",
            "dirty": False,
        }

    local = resolve_local_source_ref(
        repo_dir,
        requested_ref,
        allow_local_source=allow_local_source,
        allow_dirty_local_source=allow_dirty_local_source,
    )
    if local.get("status") in _LOCAL_GIT_OPERATIONAL_FAILURES:
        return {
            **local,
            "status": "fetch_failed",
            "source_status": str(local.get("status")),
            "remote_source_status": str(remote.get("status") or ""),
            "remote_failures": list(remote.get("failures") or []),
        }
    if local.get("status") == "user_confirmed_local_source":
        return {
            **local,
            "status": "resolved",
            "source_status": "user_confirmed_local_source",
            "remote_source_status": str(remote.get("status") or ""),
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
        "remote_source_status": str(remote.get("status") or ""),
        "local_candidate_commit": str(local.get("local_candidate_commit") or ""),
        "dirty": bool(local.get("dirty")),
    }


__all__ = ["resolve_step1_ref"]

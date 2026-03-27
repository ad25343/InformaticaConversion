# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
GitHub Pull Request integration (v2.10.0).

After Gate 3 approval the tool automatically:
  1. Creates a branch:  informatica/{mapping_name_slug}/{job_id_short}
  2. Commits all generated code and test files to that branch
  3. Opens a draft PR against the configured base branch with a structured
     description covering stack, complexity, coverage, equivalence, and
     the three human-review decisions.

Configuration (.env):
  GITHUB_TOKEN        Personal Access Token or GitHub App token (required)
  GITHUB_REPO         "owner/repo" or "org/repo"            (required)
  GITHUB_BASE_BRANCH  Target branch for PRs (default: main)
  GITHUB_API_URL      Override for GitHub Enterprise Server
                      (default: https://api.github.com)

All failures are non-fatal — if PR creation fails the job still completes
and the error is logged as a warning.  The PR URL is stored in state under
state["pr_url"] when creation succeeds.
"""
from __future__ import annotations

import base64
import logging
import re
from datetime import datetime, timezone

import httpx

from .config import settings

_log = logging.getLogger("conversion.git_pr")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _slug(text: str) -> str:
    """Convert arbitrary text to a safe git branch name segment."""
    s = re.sub(r"[^a-zA-Z0-9]+", "-", text).strip("-").lower()
    return s[:50] or "mapping"


def _headers() -> dict:
    return {
        "Authorization":        f"Bearer {settings.github_token}",
        "Accept":               "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent":           f"Informatica-Conversion-Tool/{settings.app_version}",
    }


def _api(path: str) -> str:
    base = settings.github_api_url.rstrip("/")
    repo = settings.github_repo.strip("/")
    return f"{base}/repos/{repo}/{path.lstrip('/')}"


# ── PR description builder ────────────────────────────────────────────────────

def _sorted_file_list(files: dict) -> str:
    """Return a markdown bullet list of sorted file keys."""
    return "\n".join(f"- `{f}`" for f in sorted(files.keys()))


def _gate2_fields(sign2: dict) -> tuple[str, str]:
    """Return (r2_name, gate2_decision) derived from the security sign-off."""
    if sign2:
        return sign2.get("reviewer_name", "—"), sign2.get("decision", "APPROVED")
    return "auto-approved (clean scan)", "APPROVED"


def _degraded_note(parse_ok: bool) -> str:
    """Return the parse-degraded warning block, or empty string."""
    if parse_ok:
        return ""
    return (
        "\n> ⚠️ **Parse degraded** — some source fields could not be fully resolved. "
        "Review TODO stubs before merging.\n"
    )


def _extract_pr_data(state: dict, filename: str) -> dict:
    """Extract all template variables from state for _build_pr_body."""
    conv     = state.get("conversion", {})
    review   = state.get("code_review", {})
    tests    = state.get("test_report", {})
    recon    = state.get("reconciliation", {})
    sign1    = state.get("sign_off", {})
    sign2    = state.get("security_sign_off", {})
    sign3    = state.get("code_sign_off", {})
    complex_ = state.get("complexity", {})
    eq       = review.get("equivalence_report") or {}
    files    = conv.get("files", {})
    test_files = tests.get("test_files", {})

    r2, gate2_decision = _gate2_fields(sign2)
    test_list = _sorted_file_list(test_files) if test_files else "_none_"

    return {
        "mapping_name":  conv.get("mapping_name", filename),
        "target_stack":  conv.get("target_stack", "unknown"),
        "tier":          complex_.get("tier", "unknown"),
        "r1":            sign1.get("reviewer_name", "—"),
        "r2":            r2,
        "r3":            sign3.get("reviewer_name", "—"),
        "gate2_decision": gate2_decision,
        "cov_pct":       tests.get("coverage_pct", 0),
        "fields_cov":    tests.get("fields_covered", 0),
        "fields_miss":   tests.get("fields_missing", 0),
        "eq_v":          eq.get("total_verified", "—"),
        "eq_nr":         eq.get("total_needs_review", "—"),
        "eq_m":          eq.get("total_mismatches", "—"),
        "rec_status":    recon.get("final_status", "—"),
        "rec_rate":      recon.get("match_rate", 0),
        "rec_cr":        review.get("recommendation", "—"),
        "checks_pass":   review.get("total_passed", "—"),
        "checks_fail":   review.get("total_failed", "—"),
        "file_list":     _sorted_file_list(files),
        "test_list":     test_list,
        "degraded_note": _degraded_note(conv.get("parse_ok", True)),
        "job_id":        state.get("job_id", "—"),
    }


def _build_pr_body(state: dict, filename: str, branch: str) -> str:
    d   = _extract_pr_data(state, filename)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""## Informatica Conversion: `{d['mapping_name']}`

Automatically generated by the **Informatica Conversion Tool v{settings.app_version}**.
Branch: `{branch}`
{d['degraded_note']}
---

### Mapping Details

| Property | Value |
|---|---|
| **Source file** | `{filename}` |
| **Target stack** | {d['target_stack']} |
| **Complexity tier** | {d['tier']} |

### Quality Summary

| Check | Result |
|---|---|
| **Test coverage** | {d['cov_pct']}% ({d['fields_cov']} covered / {d['fields_miss']} missing) |
| **Code review** | {d['rec_cr']} ({d['checks_pass']} passed / {d['checks_fail']} failed) |
| **Logic equivalence** | {d['eq_v']} verified / {d['eq_nr']} needs review / {d['eq_m']} mismatches |
| **Structural reconciliation** | {d['rec_status']} ({d['rec_rate']:.1f}% match rate) |

### Generated Files

**Code**
{d['file_list'] or '_none_'}

**Tests**
{d['test_list']}

### Review Gates

| Gate | Decision | Reviewer |
|---|---|---|
| Gate 1 — Human Sign-off | ✅ APPROVED | {d['r1']} |
| Gate 2 — Security Review | ✅ {d['gate2_decision']} | {d['r2']} |
| Gate 3 — Code Sign-off | ✅ APPROVED | {d['r3']} |

---
*Generated {now} · Job ID: `{d['job_id']}`*
*[Informatica Conversion Tool](https://github.com/ad25343/InformaticaConversion)*
"""


# ── Main entry point ──────────────────────────────────────────────────────────

async def _get_base_sha(client: httpx.AsyncClient, base: str) -> str | None:
    """Fetch the SHA of the base branch tip; return None if the branch is not found."""
    r = await client.get(_api(f"git/ref/heads/{base}"))
    if r.status_code == 404:
        _log.warning("GitHub PR: base branch '%s' not found in %s — skipping.",
                     base, settings.github_repo)
        return None
    r.raise_for_status()
    return r.json()["object"]["sha"]


async def _create_branch(client: httpx.AsyncClient, branch: str, base_sha: str) -> None:
    """Create *branch* at *base_sha*; silently reuse if it already exists."""
    r = await client.post(_api("git/refs"), json={
        "ref": f"refs/heads/{branch}",
        "sha": base_sha,
    })
    if r.status_code == 422:
        _log.info("GitHub PR: branch '%s' already exists — reusing.", branch)
    else:
        r.raise_for_status()


async def _commit_files(
    client: httpx.AsyncClient,
    branch: str,
    all_files: dict[str, str],
) -> list[str]:
    """Commit all files to *branch*; return list of committed file paths."""
    committed: list[str] = []
    for filepath, content in all_files.items():
        encoded = base64.b64encode(content.encode()).decode()
        existing = await client.get(_api(f"contents/{filepath}"), params={"ref": branch})
        payload: dict = {
            "message": f"feat: add {filepath} from Informatica conversion",
            "content": encoded,
            "branch":  branch,
        }
        if existing.status_code == 200:
            payload["sha"] = existing.json()["sha"]
        r = await client.put(_api(f"contents/{filepath}"), json=payload)
        r.raise_for_status()
        committed.append(filepath)
    _log.info("GitHub PR: committed %d file(s) to branch '%s'.", len(committed), branch)
    return committed


async def _open_pr(
    client: httpx.AsyncClient,
    mapping_name: str,
    branch: str,
    base: str,
    pr_body: str,
) -> str | None:
    """Create the GitHub PR; return URL on success, None if PR already exists."""
    r = await client.post(_api("pulls"), json={
        "title": f"[Informatica] {mapping_name}",
        "head":  branch,
        "base":  base,
        "body":  pr_body,
        "draft": True,
    })
    if r.status_code == 422 and "pull request already exists" in r.text.lower():
        _log.info("GitHub PR: PR already open for branch '%s' — skipping.", branch)
        return None
    r.raise_for_status()
    pr_url = r.json()["html_url"]
    _log.info("GitHub PR created: %s", pr_url)
    return pr_url


def _is_github_configured() -> bool:
    """Return True if both GITHUB_TOKEN and GITHUB_REPO are set."""
    return bool(settings.github_token and settings.github_repo)


async def _push_and_open_pr(
    job_id: str, state: dict, filename: str,
    mapping_name: str, branch: str, base: str,
    all_files: dict[str, str],
) -> str | None:
    """Execute the full GitHub API sequence; return PR URL or None."""
    async with httpx.AsyncClient(headers=_headers(), timeout=30) as client:
        base_sha = await _get_base_sha(client, base)
        if base_sha is None:
            return None
        await _create_branch(client, branch, base_sha)
        await _commit_files(client, branch, all_files)
        pr_body = _build_pr_body(state | {"job_id": job_id}, filename, branch)
        return await _open_pr(client, mapping_name, branch, base, pr_body)


async def create_pull_request(job_id: str, state: dict, filename: str) -> str | None:
    """
    Create a GitHub PR for the approved conversion job.

    Returns the PR URL on success, None on failure or if not configured.
    All exceptions are caught — this function is always non-fatal.
    """
    if not _is_github_configured():
        _log.debug("GitHub PR: not configured (GITHUB_TOKEN or GITHUB_REPO not set) — skipping.")
        return None

    conv         = state.get("conversion", {})
    tests        = state.get("test_report", {})
    mapping_name = conv.get("mapping_name", filename.replace(".xml", ""))
    branch       = f"informatica/{_slug(mapping_name)}/{job_id[:8]}"
    base         = settings.github_base_branch

    all_files: dict[str, str] = {}
    all_files.update(conv.get("files", {}))
    all_files.update(tests.get("test_files", {}))

    try:
        return await _push_and_open_pr(
            job_id, state, filename, mapping_name, branch, base, all_files
        )
    except httpx.HTTPStatusError as exc:
        _log.warning(
            "GitHub PR: HTTP error %d — %s (non-fatal)",
            exc.response.status_code, exc.response.text[:300],
        )
    except Exception as exc:
        _log.warning("GitHub PR: failed (non-fatal) — %s", exc)

    return None

#!/usr/bin/env python3
"""
Upsert ONE tracking GitHub Issue for post-merge / nightly Critical+High findings.

- Finds an existing open issue carrying marker <!-- mobile-secgate-tracking -->.
- If found: edits the body in place (preserves comments/discussion).
- If not  : creates a new one with the `security` + `auto-generated` labels.
- If totals[critical]+totals[high] == 0: closes the existing tracking issue.

Env: GITHUB_TOKEN, REPO, RUN_URL
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import requests

MARKER = "<!-- mobile-secgate-tracking -->"
API    = "https://api.github.com"


def find_issue(repo: str, headers: dict) -> dict | None:
    r = requests.get(
        f"{API}/repos/{repo}/issues",
        headers=headers,
        params={"state": "open", "labels": "auto-generated,security", "per_page": 100},
        timeout=30,
    )
    r.raise_for_status()
    for issue in r.json():
        if "pull_request" in issue:        # /issues returns PRs too
            continue
        if MARKER in (issue.get("body") or ""):
            return issue
    return None


def render_body(summary: dict, run_url: str) -> str:
    totals = summary.get("totals", {})
    by_tool = summary.get("by_tool", {})

    lines = [
        MARKER,
        "# Open Critical/High security findings (post-merge tracking)",
        "",
        f"- Run: {run_url}",
        f"- Total findings: **{summary.get('findings_count', 0)}**",
        f"- Critical: **{totals.get('critical', 0)}**, High: **{totals.get('high', 0)}**, "
        f"Medium: {totals.get('medium', 0)}, Low: {totals.get('low', 0)}",
        "",
        "| Tool | Critical | High | Medium |",
        "|------|---------:|-----:|-------:|",
    ]
    for tool, counts in sorted(by_tool.items()):
        c = counts if isinstance(counts, dict) else {}
        lines.append(f"| `{tool}` | {c.get('critical', 0)} | {c.get('high', 0)} | {c.get('medium', 0)} |")
    lines += [
        "",
        "Findings detail: see SARIF in the **Security → Code scanning** tab",
        "or the `post-merge-bundle` artifact on the linked run.",
        "",
        "_This issue is updated in place by the post-merge scan workflow._",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--summary", required=True, type=Path)
    args = ap.parse_args()

    token = os.environ["GITHUB_TOKEN"]
    repo  = os.environ["REPO"]
    run   = os.environ.get("RUN_URL", "")
    h     = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}

    summary = json.loads(args.summary.read_text())
    totals  = summary.get("totals", {})
    blocking = totals.get("critical", 0) + totals.get("high", 0)

    existing = find_issue(repo, h)

    # Nothing to track — close any existing tracking issue.
    if blocking == 0:
        if existing:
            requests.post(
                f"{API}/repos/{repo}/issues/{existing['number']}/comments",
                headers=h,
                json={"body": f"All Critical/High cleared as of {run}. Closing."},
                timeout=30,
            )
            requests.patch(
                f"{API}/repos/{repo}/issues/{existing['number']}",
                headers=h, json={"state": "closed"}, timeout=30,
            )
            print(f"closed tracking issue #{existing['number']}")
        else:
            print("no blocking findings, no tracking issue — nothing to do")
        return 0

    body = render_body(summary, run)
    title = f"Open security findings: {totals.get('critical', 0)} crit / {totals.get('high', 0)} high"

    if existing:
        r = requests.patch(
            f"{API}/repos/{repo}/issues/{existing['number']}",
            headers=h, json={"title": title, "body": body}, timeout=30,
        )
        r.raise_for_status()
        print(f"updated tracking issue #{existing['number']}")
    else:
        r = requests.post(
            f"{API}/repos/{repo}/issues",
            headers=h,
            json={
                "title": title,
                "body":  body,
                "labels": ["security", "auto-generated"],
            },
            timeout=30,
        )
        r.raise_for_status()
        print(f"created tracking issue #{r.json()['number']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

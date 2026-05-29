#!/usr/bin/env python3
"""
Aggregate scan output from SAST / Secrets / SCA / DAST / IaC / RASP into a
single severity-bucketed summary, then upsert a sticky comment on the PR.

Inputs (under --artifacts):
  scan-artifacts/sast-results/{semgrep.sarif,mobsfscan.sarif,mobsfscan.json}
  scan-artifacts/secret-results/{results.sarif,trufflehog.json}
  scan-artifacts/sca-results/{dc-report/dependency-check-report.sarif,trivy-fs.sarif}
  scan-artifacts/iac-results/trivy-iac.sarif
  scan-artifacts/dast-results/mobsf-report.json
  scan-artifacts/rasp-results/rasp-report.json

Output:
  summary.json   — machine-readable totals consumed by severity-gate.py
  PR comment     — sticky upsert via marker comment <!-- mobile-secgate -->
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import requests

MARKER = "<!-- mobile-secgate -->"
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


# ---------------------------------------------------------------------------
# Severity normalization
# ---------------------------------------------------------------------------
def norm_sev(value: str | None) -> str:
    if not value:
        return "info"
    v = str(value).strip().lower()
    if v in ("critical", "crit", "blocker"):
        return "critical"
    if v in ("high", "error", "severe"):
        return "high"
    if v in ("medium", "warning", "moderate"):
        return "medium"
    if v in ("low", "minor", "note"):
        return "low"
    return "info"


def sarif_rule_sev(rule: dict) -> str:
    props = (rule or {}).get("properties") or {}
    return norm_sev(props.get("security-severity") or props.get("severity"))


# ---------------------------------------------------------------------------
# Parsers — each returns list[dict(tool, severity, title, file, line, url)]
# ---------------------------------------------------------------------------
def parse_sarif(path: Path, tool: str) -> list[dict]:
    findings: list[dict] = []
    if not path.exists():
        return findings
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return findings

    for run in data.get("runs", []):
        rules = {r["id"]: r for r in (run.get("tool", {}).get("driver", {}).get("rules") or [])}
        for res in run.get("results", []):
            rule_id = res.get("ruleId", "")
            rule = rules.get(rule_id, {})

            sev = norm_sev(res.get("level"))
            if sev == "info":
                sev = sarif_rule_sev(rule)

            msg = (res.get("message") or {}).get("text") or rule.get("shortDescription", {}).get("text") or rule_id
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {}) or {}
            f = loc.get("artifactLocation", {}).get("uri", "")
            line = (loc.get("region") or {}).get("startLine")

            findings.append(
                {
                    "tool": tool,
                    "rule": rule_id,
                    "severity": sev,
                    "title": msg[:240],
                    "file": f,
                    "line": line,
                }
            )
    return findings


def parse_gitleaks_sarif(path: Path) -> list[dict]:
    """Gitleaks SARIF lacks severity. Treat every finding as critical — a leaked
    secret is, by definition, the highest-priority class for mobile apps."""
    findings: list[dict] = []
    if not path.exists():
        return findings
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return findings

    for run in data.get("runs", []):
        for res in run.get("results", []):
            rule_id = res.get("ruleId", "secret")
            msg     = (res.get("message") or {}).get("text") or rule_id
            loc     = (res.get("locations") or [{}])[0].get("physicalLocation", {}) or {}
            f       = loc.get("artifactLocation", {}).get("uri", "")
            line    = (loc.get("region") or {}).get("startLine")
            findings.append({
                "tool":     "gitleaks",
                "rule":     rule_id,
                "severity": "critical",
                "title":    msg[:240],
                "file":     f,
                "line":     line,
            })
    return findings


def parse_trufflehog(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out: list[dict] = []
    text = path.read_text().strip()
    if not text:
        return []
    # Trufflehog emits NDJSON when streamed; a single JSON array when --json --output
    candidates = []
    if text.startswith("["):
        try:
            candidates = json.loads(text)
        except json.JSONDecodeError:
            candidates = []
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                candidates.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    for item in candidates:
        verified = item.get("Verified") or item.get("verified")
        det = item.get("DetectorName") or item.get("detector_name") or "Secret"
        src = item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
        out.append(
            {
                "tool": "trufflehog",
                "rule": det,
                "severity": "critical" if verified else "high",
                "title": f"Verified secret: {det}" if verified else f"Possible secret: {det}",
                "file": src.get("file", ""),
                "line": src.get("line"),
            }
        )
    return out


def parse_mobsfscan_json(path: Path) -> list[dict]:
    """mobsfscan --json output. Has severity in metadata.severity (HIGH/WARNING/INFO/GOOD/ERROR)."""
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return []

    findings: list[dict] = []
    results = data.get("results") or {}
    if not isinstance(results, dict):
        return findings

    for rule_id, body in results.items():
        if not isinstance(body, dict):
            continue
        meta = body.get("metadata") or {}
        # mobsfscan severities: ERROR/WARNING/INFO/GOOD + sometimes HIGH
        raw = meta.get("severity") or body.get("severity") or ""
        sev = norm_sev(raw)
        # GOOD = compliance pass — skip it
        if str(raw).strip().upper() == "GOOD":
            continue
        title = meta.get("description") or rule_id
        files = body.get("files") or []
        if files and isinstance(files, list):
            for f in files:
                findings.append({
                    "tool":     "mobsfscan",
                    "rule":     rule_id,
                    "severity": sev,
                    "title":    str(title)[:240],
                    "file":     (f.get("file_path") if isinstance(f, dict) else str(f)) or "",
                    "line":     (f.get("match_lines", [None])[0] if isinstance(f, dict) else None),
                })
        else:
            # Missing-control finding (no file location). Keep it as info — these
            # are "you didn't implement X" advisories.
            findings.append({
                "tool":     "mobsfscan",
                "rule":     rule_id,
                "severity": sev,
                "title":    str(title)[:240],
                "file":     "",
                "line":     None,
            })
    return findings


def parse_mobsf_report(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return []

    findings: list[dict] = []

    # MobSF lumps findings under several keys depending on platform/version.
    for bucket in ("code_analysis", "manifest_analysis", "permissions",
                   "binary_analysis", "network_security", "secrets"):
        section = data.get(bucket) or {}
        if isinstance(section, dict):
            findings_dict = section.get("findings") or section
            for rule_id, body in findings_dict.items() if isinstance(findings_dict, dict) else []:
                if not isinstance(body, dict):
                    continue
                sev = norm_sev(body.get("severity") or body.get("metadata", {}).get("severity"))
                title = body.get("metadata", {}).get("description") or body.get("description") or rule_id
                files = body.get("files") or []
                if files and isinstance(files, list):
                    for f in files:
                        findings.append(
                            {
                                "tool": "mobsf",
                                "rule": rule_id,
                                "severity": sev,
                                "title": str(title)[:240],
                                "file": (f.get("file_path") if isinstance(f, dict) else str(f)) or "",
                                "line": (f.get("match_lines", [None])[0] if isinstance(f, dict) else None),
                            }
                        )
                else:
                    findings.append(
                        {
                            "tool": "mobsf",
                            "rule": rule_id,
                            "severity": sev,
                            "title": str(title)[:240],
                            "file": "",
                            "line": None,
                        }
                    )
    return findings


def parse_rasp(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return []
    out = []
    for issue in data.get("issues", []):
        out.append(
            {
                "tool": "rasp-check",
                "rule": issue.get("id", "RASP_MISSING"),
                "severity": norm_sev(issue.get("severity", "high")),
                "title": issue.get("message", "freeRASP integration missing"),
                "file": issue.get("file", ""),
                "line": issue.get("line"),
            }
        )
    return out


# ---------------------------------------------------------------------------
# Comment rendering
# ---------------------------------------------------------------------------
def render_comment(by_tool: dict[str, list[dict]], totals: dict[str, int]) -> str:
    badge = lambda n, s: f"![{s}](https://img.shields.io/badge/{s.title()}-{n}-{COLOR[s]})"

    head = [
        MARKER,
        "## Mobile DevSecOps — PR Security Gate",
        "",
        " | ".join(badge(totals.get(s, 0), s) for s in SEV_ORDER),
        "",
        "| Tool | Critical | High | Medium | Low | Info |",
        "|------|---------:|-----:|-------:|----:|-----:|",
    ]
    for tool, findings in sorted(by_tool.items()):
        c = Counter(f["severity"] for f in findings)
        head.append(
            f"| `{tool}` | {c['critical']} | {c['high']} | {c['medium']} | {c['low']} | {c['info']} |"
        )

    parts = ["\n".join(head), ""]

    for tool, findings in sorted(by_tool.items()):
        if not findings:
            continue
        findings = sorted(findings, key=lambda x: SEV_ORDER.index(x["severity"]))[:25]
        rows = ["", f"<details><summary><b>{tool}</b> — top {len(findings)} findings</summary>", "",
                "| Severity | Rule | Title | Location |",
                "|----------|------|-------|----------|"]
        for f in findings:
            loc = f"{f['file']}:{f['line']}" if f["line"] else (f["file"] or "—")
            rows.append(f"| {f['severity'].upper()} | `{f['rule']}` | {f['title']} | `{loc}` |")
        rows.append("\n</details>")
        parts.append("\n".join(rows))

    gate = "merge **BLOCKED** — fix Critical/High findings" if (totals.get("critical", 0) + totals.get("high", 0)) else "gate **GREEN** — no Critical/High findings"
    parts.append(f"\n> {gate}")
    return "\n".join(parts)


COLOR = {
    "critical": "red",
    "high": "orange",
    "medium": "yellow",
    "low": "blue",
    "info": "lightgrey",
}


# ---------------------------------------------------------------------------
# GitHub sticky-comment upsert
# ---------------------------------------------------------------------------
def upsert_comment(repo: str, pr: int, token: str, body: str) -> None:
    api = f"https://api.github.com/repos/{repo}/issues/{pr}/comments"
    h = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}

    r = requests.get(api, headers=h, timeout=30)
    r.raise_for_status()
    for c in r.json():
        if MARKER in (c.get("body") or ""):
            patch = requests.patch(c["url"], headers=h, json={"body": body}, timeout=30)
            patch.raise_for_status()
            print(f"updated comment {c['id']}")
            return

    post = requests.post(api, headers=h, json={"body": body}, timeout=30)
    post.raise_for_status()
    print(f"created comment {post.json().get('id')}")


# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts", required=True, type=Path)
    ap.add_argument("--summary",   required=True, type=Path)
    args = ap.parse_args()

    root = args.artifacts
    by_tool: dict[str, list[dict]] = defaultdict(list)

    by_tool["semgrep"]         += parse_sarif(root / "sast-results" / "semgrep.sarif", "semgrep")
    # mobsfscan: prefer JSON (carries severity); fall back to SARIF if JSON missing
    mobsfscan_json = root / "sast-results" / "mobsfscan.json"
    if mobsfscan_json.exists():
        by_tool["mobsfscan"]   += parse_mobsfscan_json(mobsfscan_json)
    else:
        by_tool["mobsfscan"]   += parse_sarif(root / "sast-results" / "mobsfscan.sarif", "mobsfscan")
    by_tool["gitleaks"]        += parse_gitleaks_sarif(root / "secret-results" / "results.sarif")
    by_tool["trufflehog"]      += parse_trufflehog(root / "secret-results" / "trufflehog.json")
    by_tool["dependency-check"]+= parse_sarif(root / "sca-results" / "dc-report" / "dependency-check-report.sarif", "dependency-check")
    by_tool["trivy-fs"]        += parse_sarif(root / "sca-results" / "trivy-fs.sarif", "trivy-fs")
    by_tool["trivy-iac"]       += parse_sarif(root / "iac-results" / "trivy-iac.sarif", "trivy-iac")
    by_tool["mobsf"]           += parse_mobsf_report(root / "dast-results" / "mobsf-report.json")
    by_tool["rasp-check"]      += parse_rasp(root / "rasp-results" / "rasp-report.json")

    totals = Counter()
    for findings in by_tool.values():
        totals.update(f["severity"] for f in findings)

    summary = {
        "totals":  dict(totals),
        "by_tool": {t: Counter(f["severity"] for f in fs) for t, fs in by_tool.items()},
        "findings_count": sum(len(fs) for fs in by_tool.values()),
    }
    args.summary.write_text(json.dumps(summary, indent=2, default=int))

    body = render_comment(by_tool, totals)
    token = os.environ.get("GITHUB_TOKEN")
    pr    = os.environ.get("PR_NUMBER")
    repo  = os.environ.get("REPO")
    if token and pr and repo:
        upsert_comment(repo, int(pr), token, body)
    else:
        print(body)

    return 0


if __name__ == "__main__":
    sys.exit(main())

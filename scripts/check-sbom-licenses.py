#!/usr/bin/env python3
"""
Check SBOM for license compliance issues.

Reads sbom.cdx.json and flags components with licenses matching a deny list.
Outputs JSON array of findings for the PR comment aggregator.
"""
import json
import sys
from pathlib import Path

DENY_PATTERNS = [
    "GPL-2.0",
    "GPL-3.0",
    "AGPL-3.0",
    "LGPL-2.1",
    "LGPL-3.0",
    "SSPL",
    "OPL",
    "CPAL",
]


def normalize(lic) -> str:
    if not lic:
        return ""
    if isinstance(lic, str):
        return lic
    if isinstance(lic, list):
        parts = []
        for item in lic:
            if isinstance(item, dict):
                parts.append(item.get("license", {}).get("name", "") or item.get("name", ""))
            else:
                parts.append(str(item))
        return ", ".join(parts)
    return str(lic)


def main() -> int:
    sbom_path = Path("sbom.cdx.json")
    if not sbom_path.exists():
        print("[]")
        return 0

    try:
        data = json.loads(sbom_path.read_text())
    except (json.JSONDecodeError, ValueError):
        print("[]")
        return 0

    findings = []
    for comp in data.get("components", []) or []:
        lic = normalize(comp.get("licenses"))
        if not lic:
            continue
        upper = lic.upper()
        for deny in DENY_PATTERNS:
            if deny.upper() in upper:
                findings.append({
                    "tool": "sbom-license",
                    "rule": f"license-{deny.lower()}",
                    "severity": "high",
                    "title": f"License compliance issue: {lic}",
                    "file": comp.get("purl", comp.get("name", "")),
                    "line": None,
                })
                break

    print(json.dumps(findings))
    return 0


if __name__ == "__main__":
    sys.exit(main())

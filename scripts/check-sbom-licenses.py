#!/usr/bin/env python3
"""
Check SBOM and dependency manifests for license compliance issues.

Checks:
1. sbom.cdx.json components (if cdxgen resolved licenses)
2. requirements.txt for known GPL packages by name/version lookup
3. package.json for known GPL packages
4. pom.xml for known GPL packages

Outputs JSON array of findings.
"""
import json
import re
import sys
from pathlib import Path

# Deny list by SPDX identifier or common substring
DENY_PATTERNS = [
    "GPL-2.0",
    "GPL-3.0",
    "AGPL-3.0",
    "LGPL-2.1",
    "LGPL-3.0",
    "SSPL",
    "OPL",
    "CPAL",
    "GPLv2",
    "GPLv3",
    "AGPL",
    "LGPL",
]

# Known GPL packages by ecosystem (name -> reason)
KNOWN_GPL_PYPI = {
    "mysqlclient": "GPL-2.0",
    "psycopg2": "LGPL-3.0",
    "pygobject": "LGPL-2.1",
    "pyqt5": "GPL-2.0/GPL-3.0",
    "pyqt6": "GPL-2.0/GPL-3.0",
    "pyside2": "LGPL-3.0",
    "pyside6": "LGPL-3.0",
}

KNOWN_GPL_NPM = {
    "gpl-licensed-example": "GPL-3.0",
}

KNOWN_GPL_MAVEN = {
    "postgresql": "BSD but some drivers had GPL confusion",
}


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


def match_deny(lic_text: str):
    upper = lic_text.upper()
    for deny in DENY_PATTERNS:
        if deny.upper() in upper:
            return deny
    return None


def check_sbom(sbom_path: Path) -> list[dict]:
    findings = []
    if not sbom_path.exists():
        return findings
    try:
        data = json.loads(sbom_path.read_text())
    except (json.JSONDecodeError, ValueError):
        return findings

    for comp in data.get("components", []) or []:
        lic = normalize(comp.get("licenses"))
        if not lic:
            continue
        matched = match_deny(lic)
        if matched:
            findings.append({
                "tool": "sbom-license",
                "rule": f"license-{matched.lower()}",
                "severity": "high",
                "title": f"License compliance issue: {lic}",
                "file": comp.get("purl", comp.get("name", "")),
                "line": None,
            })
    return findings


def check_requirements(req_path: Path) -> list[dict]:
    findings = []
    if not req_path.exists():
        return findings
    text = req_path.read_text(errors="ignore")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        pkg = re.split(r"[=><!~\[]", line)[0].strip().lower()
        if pkg in KNOWN_GPL_PYPI:
            findings.append({
                "tool": "sbom-license",
                "rule": f"license-{KNOWN_GPL_PYPI[pkg].lower().replace('/', '-')}",
                "severity": "high",
                "title": f"License compliance issue: {pkg} ({KNOWN_GPL_PYPI[pkg]})",
                "file": str(req_path.relative_to(Path.cwd()) if req_path.is_absolute() else req_path),
                "line": None,
            })
    return findings


def check_package_json(pkg_path: Path) -> list[dict]:
    findings = []
    if not pkg_path.exists():
        return findings
    try:
        data = json.loads(pkg_path.read_text())
    except (json.JSONDecodeError, ValueError):
        return findings
    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    for pkg in deps:
        if pkg in KNOWN_GPL_NPM:
            findings.append({
                "tool": "sbom-license",
                "rule": f"license-{KNOWN_GPL_NPM[pkg].lower().replace('/', '-')}",
                "severity": "high",
                "title": f"License compliance issue: {pkg} ({KNOWN_GPL_NPM[pkg]})",
                "file": str(pkg_path.relative_to(Path.cwd()) if pkg_path.is_absolute() else pkg_path),
                "line": None,
            })
    return findings


def check_pom_xml(pom_path: Path) -> list[dict]:
    findings = []
    if not pom_path.exists():
        return findings
    text = pom_path.read_text(errors="ignore")
    for pkg in KNOWN_GPL_MAVEN:
        if f"<artifactId>{pkg}</artifactId>" in text:
            findings.append({
                "tool": "sbom-license",
                "rule": f"license-{KNOWN_GPL_MAVEN[pkg].lower().replace('/', '-')}",
                "severity": "high",
                "title": f"License compliance issue: {pkg} ({KNOWN_GPL_MAVEN[pkg]})",
                "file": str(pom_path.relative_to(Path.cwd()) if pom_path.is_absolute() else pom_path),
                "line": None,
            })
    return findings


def main() -> int:
    root = Path(".")
    findings = []
    findings += check_sbom(root / "sbom.cdx.json")
    
    # Search for dependency manifests recursively
    for req_path in root.rglob("requirements.txt"):
        findings += check_requirements(req_path)
    for pkg_path in root.rglob("package.json"):
        findings += check_package_json(pkg_path)
    for pom_path in root.rglob("pom.xml"):
        findings += check_pom_xml(pom_path)

    # Deduplicate by (file, rule)
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("file", ""), f.get("rule", ""))
        if key not in seen:
            seen.add(key)
            unique.append(f)

    print(json.dumps(unique))
    return 0


if __name__ == "__main__":
    sys.exit(main())

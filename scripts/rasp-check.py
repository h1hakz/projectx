#!/usr/bin/env python3
"""
Verify freeRASP (Talsec) is integrated.

iOS  — look for `import TalsecRuntime` / `Talsec.start(` in Swift sources
       and the `freeRASP-iOS` SPM/CocoaPods dependency.
Android — look for `com.aheaditec.talsec.security` Kotlin/Java imports and
       the `freeraspAndroid` Gradle dependency.

Emits a JSON report consumed by aggregate-and-comment.py.
Reference: https://www.talsec.app/freerasp-in-app-protection-security-talsec
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

IOS_IMPORT       = re.compile(r"\bimport\s+TalsecRuntime\b")
IOS_START_CALL   = re.compile(r"\bTalsec\s*\.\s*start\s*\(")
IOS_SPM_DEP      = re.compile(r"talsec[/-]freeRASP[\-_]?iOS", re.I)
IOS_PODS_DEP     = re.compile(r"\bpod\s+['\"]freeRASP-iOS['\"]")

AND_IMPORT       = re.compile(r"com\.aheaditec\.talsec\.security")
AND_GRADLE_DEP   = re.compile(r"com\.aheaditec\.freeraspandroid:freeraspandroid", re.I)


def looks_like_ios(root: Path) -> bool:
    return any(root.rglob("*.xcodeproj")) or any(root.rglob("Package.swift")) or any(root.rglob("Podfile"))


def looks_like_android(root: Path) -> bool:
    return any(root.rglob("build.gradle")) or any(root.rglob("build.gradle.kts")) or any(root.rglob("AndroidManifest.xml"))


def scan(paths, pattern) -> bool:
    for p in paths:
        try:
            if pattern.search(p.read_text(errors="ignore")):
                return True
        except OSError:
            continue
    return False


def check_ios(root: Path) -> list[dict]:
    swift = list(root.rglob("*.swift"))
    deps  = list(root.rglob("Package.swift")) + list(root.rglob("Podfile")) + list(root.rglob("Podfile.lock"))

    has_import = scan(swift, IOS_IMPORT)
    has_start  = scan(swift, IOS_START_CALL)
    has_dep    = scan(deps, IOS_SPM_DEP) or scan(deps, IOS_PODS_DEP)

    dep_file = next((p for p in deps if p.exists()), None)
    swift_file = next(iter(swift), None) if swift else None

    issues = []
    if not has_dep:
        issues.append({
            "id": "RASP_IOS_DEP_MISSING",
            "severity": "high",
            "message": "freeRASP-iOS dependency not declared in Package.swift / Podfile",
            "file": str(dep_file.relative_to(root)) if dep_file else "",
        })
    if not has_import:
        issues.append({
            "id": "RASP_IOS_IMPORT_MISSING",
            "severity": "high",
            "message": "No Swift source imports `TalsecRuntime`",
            "file": str(swift_file.relative_to(root)) if swift_file else "",
        })
    if not has_start:
        issues.append({
            "id": "RASP_IOS_START_MISSING",
            "severity": "critical",
            "message": "freeRASP not initialized — `Talsec.start(...)` call not found",
            "file": str(swift_file.relative_to(root)) if swift_file else "",
        })
    return issues


def check_android(root: Path) -> list[dict]:
    src   = list(root.rglob("*.kt")) + list(root.rglob("*.java"))
    build = list(root.rglob("build.gradle")) + list(root.rglob("build.gradle.kts"))

    has_import = scan(src,   AND_IMPORT)
    has_dep    = scan(build, AND_GRADLE_DEP)

    build_file = next((p for p in build if p.exists()), None)
    src_file = next(iter(src), None) if src else None

    issues = []
    if not has_dep:
        issues.append({
            "id": "RASP_ANDROID_DEP_MISSING",
            "severity": "high",
            "message": "freeraspAndroid Gradle dependency missing",
            "file": str(build_file.relative_to(root)) if build_file else "",
        })
    if not has_import:
        issues.append({
            "id": "RASP_ANDROID_INIT_MISSING",
            "severity": "critical",
            "message": "No source imports `com.aheaditec.talsec.security` — RASP not initialized",
            "file": str(src_file.relative_to(root)) if src_file else "",
        })
    return issues


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root",   default=".",            type=Path)
    ap.add_argument("--report", default="rasp-report.json", type=Path)
    args = ap.parse_args()

    root = args.root.resolve()
    platforms = []
    issues: list[dict] = []

    if looks_like_ios(root):
        platforms.append("ios")
        issues += check_ios(root)
    if looks_like_android(root):
        platforms.append("android")
        issues += check_android(root)

    if not platforms:
        issues.append({
            "id": "RASP_PLATFORM_UNKNOWN",
            "severity": "info",
            "message": "Could not detect iOS or Android project layout — RASP check skipped",
        })

    report = {
        "platforms_detected": platforms,
        "rasp_provider": "freeRASP (Talsec)",
        "reference": "https://www.talsec.app/freerasp-in-app-protection-security-talsec",
        "issues": issues,
    }
    args.report.write_text(json.dumps(report, indent=2))
    print(f"freeRASP check — platforms={platforms}, issues={len(issues)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

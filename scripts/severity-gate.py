#!/usr/bin/env python3
"""Fail the workflow when any forbidden severity bucket has > 0 findings."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--summary", required=True, type=Path)
    ap.add_argument("--fail-on", default="critical,high",
                    help="Comma-separated severities that block the merge")
    args = ap.parse_args()

    totals = json.loads(args.summary.read_text()).get("totals", {})
    blocking = [s.strip().lower() for s in args.fail_on.split(",") if s.strip()]

    bad = {s: totals.get(s, 0) for s in blocking if totals.get(s, 0) > 0}

    if bad:
        details = ", ".join(f"{k}={v}" for k, v in bad.items())
        print(f"::error::Security gate FAILED — blocking findings: {details}")
        return 1

    print("Security gate PASSED — no blocking findings.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

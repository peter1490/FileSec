#!/usr/bin/env python3
"""Render an *unsuppressed* `cargo audit --json` report as Markdown.

CI runs cargo-audit outside the repository (so .cargo/audit.toml's ignore list
does not apply) and appends this summary to the job, so the accepted exceptions
stay visible: a green configured gate must never be read as "no known
advisories in the dependency graph". Report-only; always exits 0.

Usage: scripts/advisory_report.py report.json
"""
import json
import sys


def main():
    with open(sys.argv[1], encoding="utf-8") as fh:
        report = json.load(fh)
    rows = []
    for vuln in report.get("vulnerabilities", {}).get("list", []):
        advisory, package = vuln.get("advisory", {}), vuln.get("package", {})
        patched = ", ".join(vuln.get("versions", {}).get("patched", [])) or "none"
        rows.append((advisory.get("id"), package.get("name"), package.get("version"),
                     "vulnerability", advisory.get("title", ""), patched))
    for kind, warnings in report.get("warnings", {}).items():
        for warning in warnings:
            advisory = warning.get("advisory") or {}
            package = warning.get("package", {})
            rows.append((advisory.get("id", "—"), package.get("name"), package.get("version"),
                         kind, advisory.get("title", ""), "—"))
    print("### Unsuppressed RustSec scan (report-only)\n")
    if not rows:
        print("No advisories match any crate in Cargo.lock.")
        return 0
    print("Accepted exceptions are listed in deny.toml / .cargo/audit.toml with owners "
          "and review-by dates; anything here that is not listed there fails the gate.\n")
    print("| Advisory | Crate | Version | Kind | Title | Patched |")
    print("|---|---|---|---|---|---|")
    for row in rows:
        print("| " + " | ".join(str(cell).replace("|", "\\|") for cell in row) + " |")
    return 0


if __name__ == "__main__":
    sys.exit(main())

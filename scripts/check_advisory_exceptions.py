#!/usr/bin/env python3
"""Keep accepted RustSec advisories owned, dated, and in sync (audit: deps).

Fails (exit 1) when:
  * a deny.toml `[advisories] ignore` entry is not `{ id, reason }` with a reason
    naming an `owner:` and a `review-by: YYYY-MM-DD`;
  * a review-by date has passed, or lies more than 400 days ahead (no
    open-ended exceptions);
  * .cargo/audit.toml ignores an ID that deny.toml does not, unless the entry is
    preceded by an `# audit-only: owner: ...; review-by: ...` comment (for
    lockfile-only crates cargo-deny's shipped graph never encounters);
  * deny.toml ignores an ID that .cargo/audit.toml does not.

Usage: scripts/check_advisory_exceptions.py [--today YYYY-MM-DD]
"""
import argparse
import datetime
import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATE = re.compile(r"review-by:\s*(\d{4}-\d{2}-\d{2})")
OWNER = re.compile(r"owner:\s*\S+")
MAX_AHEAD = datetime.timedelta(days=400)


def check_reason(where, reason, today, errors):
    if not OWNER.search(reason):
        errors.append(f"{where}: no 'owner:' in {reason!r}")
    match = DATE.search(reason)
    if not match:
        errors.append(f"{where}: no 'review-by: YYYY-MM-DD' in {reason!r}")
        return
    due = datetime.date.fromisoformat(match.group(1))
    if due < today:
        errors.append(f"{where}: review-by {due} has passed — re-assess, then fix or re-date it")
    elif due - today > MAX_AHEAD:
        errors.append(f"{where}: review-by {due} is more than {MAX_AHEAD.days} days ahead")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--today", type=datetime.date.fromisoformat, default=datetime.date.today())
    args = parser.parse_args()
    errors = []

    deny = tomllib.loads((ROOT / "deny.toml").read_text())
    deny_ids = set()
    for entry in deny.get("advisories", {}).get("ignore", []):
        if not isinstance(entry, dict) or "id" not in entry or "reason" not in entry:
            errors.append(f"deny.toml: ignore entry {entry!r} must be {{ id, reason }}")
            continue
        deny_ids.add(entry["id"])
        check_reason(f"deny.toml {entry['id']}", entry["reason"], args.today, errors)

    audit_text = (ROOT / ".cargo" / "audit.toml").read_text()
    audit_ids = set(tomllib.loads(audit_text).get("advisories", {}).get("ignore", []))
    lines = audit_text.splitlines()
    for advisory in sorted(audit_ids - deny_ids):
        index = next(i for i, line in enumerate(lines) if f'"{advisory}"' in line)
        comment = []
        for line in reversed(lines[:index]):
            if not line.strip().startswith("#"):
                break
            comment.insert(0, line.strip().lstrip("#").strip())
        text = " ".join(comment)
        if "audit-only:" not in text:
            errors.append(f".cargo/audit.toml {advisory}: not in deny.toml and not marked '# audit-only:'")
        else:
            check_reason(f".cargo/audit.toml {advisory}", text, args.today, errors)
    for advisory in sorted(deny_ids - audit_ids):
        errors.append(f"deny.toml {advisory}: missing from .cargo/audit.toml (keep them in lockstep)")

    if errors:
        print("Advisory exception policy violations:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(f"{len(deny_ids | audit_ids)} accepted advisories: all owned, dated, and in sync.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

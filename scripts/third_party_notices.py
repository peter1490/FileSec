#!/usr/bin/env python3
"""Generate THIRD_PARTY_NOTICES.txt for one shipped FileSec binary (audit FS-18).

The notice bundle lists every crate linked into the binary for one target —
walked from the binary's package through the *locked* dependency graph
(normal dependencies only; dev/build-only crates are not distributed) — with
its version, SPDX license expression, and the full text of every license /
notice / copyright file the crate ships, followed by the licenses of the fonts
embedded in the application. Identical license texts are printed once and
referenced by id, which keeps the bundle readable.

The crate sources must already be present locally (run it after
`cargo build --locked` or `cargo fetch --locked`).

Usage:
    third_party_notices.py --package filesec-gui --target x86_64-unknown-linux-gnu \\
        --out target/release/THIRD_PARTY_NOTICES.txt

`cargo deny` checks that licenses are *allowed*; this bundle is what satisfies
their redistribution terms. Review its output before relying on it for a
legal determination.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys

LICENSE_PREFIXES = ("license", "licence", "copying", "notice", "copyright", "unlicense")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FONTS_DIR = os.path.join(REPO_ROOT, "crates", "filesec-gui", "assets", "fonts")
EMBEDDED_ASSETS = (
    ("Inter (InterVariable.ttf)", "OFL-1.1", "Inter-LICENSE.txt"),
    ("Phosphor Icons (Phosphor.ttf)", "MIT", "Phosphor-LICENSE.txt"),
)


def cargo_metadata(target):
    cmd = [
        "cargo",
        "metadata",
        "--format-version",
        "1",
        "--locked",
        "--all-features",
        "--filter-platform",
        target,
    ]
    out = subprocess.run(cmd, cwd=REPO_ROOT, check=True, capture_output=True, text=True)
    return json.loads(out.stdout)


def linked_packages(meta, root_name):
    packages = {p["id"]: p for p in meta["packages"]}
    roots = [p["id"] for p in meta["packages"] if p["name"] == root_name and p["source"] is None]
    if len(roots) != 1:
        sys.exit(f"third_party_notices: workspace package {root_name!r} not found")
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    seen, stack = set(), [roots[0]]
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        for dep in nodes[pid]["deps"]:
            # Only normal (linked) dependency edges; skip dev/build-only ones.
            if any(kind["kind"] is None for kind in dep["dep_kinds"]):
                stack.append(dep["pkg"])
    return sorted(
        (packages[pid] for pid in seen),
        key=lambda p: (p["name"], p["version"]),
    )


def is_license_name(name, in_font_dir):
    lower = name.lower()
    if lower.endswith((".rs", ".toml", ".lock", ".json", ".ttf", ".otf")):
        return False
    if lower.startswith(LICENSE_PREFIXES) or "license" in lower or "licence" in lower:
        return True
    # Font directories ship their license as e.g. OFL.txt, UFL.txt, Hack-Regular.txt.
    return in_font_dir and lower.endswith(".txt")


def license_files(package):
    """Every license/notice file the crate ships: at its root, in nested
    directories (bundled assets such as fonts carry their own), and the
    manifest's `license-file`."""
    root = os.path.dirname(package["manifest_path"])
    found = set()
    for dirpath, dirnames, filenames in os.walk(root):
        depth = os.path.relpath(dirpath, root).count(os.sep)
        dirnames[:] = [
            d for d in dirnames if d not in ("target", ".git", "tests", "benches", "examples")
        ]
        if depth >= 3:
            dirnames[:] = []
        in_font_dir = "font" in os.path.basename(dirpath).lower()
        for name in filenames:
            if is_license_name(name, in_font_dir):
                found.add(os.path.join(dirpath, name))
    declared = package.get("license_file")
    if declared:
        path = os.path.normpath(os.path.join(root, declared))
        if os.path.isfile(path):
            found.add(path)
    return sorted(found)


# File-name suffixes that identify which license a crate's file carries, used to
# find a representative text for crates that ship no license file of their own.
SPDX_BY_FILE_SUFFIX = {
    "mit": "MIT",
    "apache": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "zlib": "Zlib",
    "bsl": "BSL-1.0",
    "boost": "BSL-1.0",
    "isc": "ISC",
    "unicode": "Unicode-3.0",
}


def spdx_ids(expression):
    """The license identifiers in an SPDX expression (operators dropped)."""
    if not expression:
        return []
    cleaned = expression.replace("(", " ").replace(")", " ").replace("/", " OR ")
    return [tok for tok in cleaned.split() if tok not in ("OR", "AND", "WITH")]


def spdx_of_file(name, expression):
    lower = name.lower()
    for sep in ("-", "_", "."):
        if sep in lower:
            suffix = lower.split(sep, 1)[1].rsplit(".txt", 1)[0].rsplit(".md", 1)[0]
            if suffix in SPDX_BY_FILE_SUFFIX:
                return SPDX_BY_FILE_SUFFIX[suffix]
    ids = spdx_ids(expression)
    return ids[0] if len(ids) == 1 else None


def read_text(path):
    with open(path, "rb") as fh:
        return fh.read().decode("utf-8", errors="replace").replace("\r\n", "\n").strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--package", required=True, help="workspace package of the binary")
    parser.add_argument("--target", required=True, help="target triple the binary is built for")
    parser.add_argument("--out", required=True, help="output path")
    args = parser.parse_args()

    meta = cargo_metadata(args.target)
    crates = linked_packages(meta, args.package)
    texts = {}  # sha256 -> (id, text)
    representative = {}  # SPDX id -> text id of a crate file carrying it
    entries = []
    for package in crates:
        if package["source"] is None:
            continue  # FileSec's own workspace crates
        refs = []
        for path in license_files(package):
            text = read_text(path)
            if not text:
                continue
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            if digest not in texts:
                texts[digest] = (f"T{len(texts) + 1}", text)
            ref = texts[digest][0]
            label = os.path.relpath(path, os.path.dirname(package["manifest_path"]))
            refs.append((label.replace(os.sep, "/"), ref))
            spdx = spdx_of_file(os.path.basename(path), package.get("license"))
            if spdx:
                representative.setdefault(spdx, ref)
        entries.append((package, refs))

    version = next(
        (p["version"] for p in meta["packages"] if p["name"] == args.package and p["source"] is None),
        "?",
    )
    lines = [
        "FileSec — third-party notices",
        "=============================",
        "",
        f"Binary package: {args.package} {version}",
        f"Target: {args.target}",
        "FileSec itself is licensed under MIT OR Apache-2.0.",
        "",
        "This file accompanies every FileSec distribution. It lists the software",
        "embedded in or linked into this binary, with the license terms each one",
        "requires to be passed on. Identical license texts are printed once in the",
        "appendix and referenced by id (for example [T3]).",
        "",
        "",
        "1. Embedded assets",
        "------------------",
    ]
    for title, spdx, filename in EMBEDDED_ASSETS:
        lines += ["", f"{title} — {spdx}", "", read_text(os.path.join(FONTS_DIR, filename)), ""]
    lines += [
        "",
        f"2. Rust crates linked into {args.package} ({len(entries)})",
        "-" * 40,
        "",
    ]
    for package, refs in entries:
        lines.append(
            f"{package['name']} {package['version']} — {package.get('license') or 'see files'}"
        )
        if package.get("repository"):
            lines.append(f"  source: {package['repository']}")
        if refs:
            for name, ref in refs:
                lines.append(f"  {name}: [{ref}]")
        else:
            lines.append("  (the published crate ships no license file of its own;")
            generic = [
                f"{spdx}: [{representative[spdx]}]"
                for spdx in spdx_ids(package.get("license"))
                if spdx in representative
            ]
            lines.append(
                "   the standard text of its license: " + ", ".join(generic) + ")"
                if generic
                else "   see its source repository for the license text)"
            )
    lines += ["", "", "3. License texts", "----------------"]
    for ref, text in sorted(texts.values(), key=lambda item: int(item[0][1:])):
        lines += ["", f"[{ref}]", "", text, ""]

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"wrote {args.out}: {len(entries)} crates, {len(texts)} distinct license texts")


if __name__ == "__main__":
    main()

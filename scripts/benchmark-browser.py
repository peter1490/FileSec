#!/usr/bin/env python3
"""Benchmark actual browser helpers against a Git revision (default: HEAD).

Runs a Rust-optimized microbenchmark of row preparation, not disk I/O or painting.
Requires only Python, Git and rustc. Temporary build files are removed on exit.
Usage: python3 scripts/benchmark-browser.py [baseline-revision]
"""
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = 'crates/filesec-gui/src/app.rs'


def item(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def module(name, source):
    signatures = ['struct Row', 'fn parent_dir(', 'fn leaf_name(',
                  'fn visible_rows(', 'fn sort_rows(']
    if 'fn dir_child_count(' in source:
        signatures.append('fn dir_child_count(')
    body = '\n'.join(item(source, signature) for signature in signatures)
    return 'mod ' + name + ' { use super::*;\n' + body + r'''
    pub fn rows(entries: &[(String, EntryKind, u64)], search: &str, sort: SortMode)
        -> Vec<(String, EntryKind, u64, usize)> {
        visible_rows(entries, "", search, sort).into_iter()
            .map(|r| (r.path, r.kind, r.size, r.children)).collect()
    }
    pub fn measure(entries: &[(String, EntryKind, u64)]) -> u128 {
        let start = std::time::Instant::now();
        std::hint::black_box(visible_rows(std::hint::black_box(entries), "", "", SortMode::NameAsc));
        start.elapsed().as_micros()
    }
}
'''


revision = sys.argv[1] if len(sys.argv) > 1 else 'HEAD'
baseline = subprocess.check_output(['git', 'show', f'{revision}:{SOURCE}'], cwd=ROOT, text=True)
current = (ROOT / SOURCE).read_text()
program = r'''
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum EntryKind { File, Dir }
#[derive(Clone, Copy)]
enum SortMode { NameAsc, NameDesc, SizeDesc, SizeAsc }
fn is_trashed(path: &str) -> bool { path == ".trash" || path.starts_with(".trash/") }
'''
program += module('before', baseline) + module('after', current)
program += r'''
fn main() {
    let mut entries = Vec::new();
    for i in (0..5000).rev() {
        entries.push((format!("folder-{i:05}"), EntryKind::Dir, 0));
        for j in 0..3 {
            entries.push((format!("folder-{i:05}/file-{j}.txt"), EntryKind::File, j));
        }
    }
    for sort in [SortMode::NameAsc, SortMode::NameDesc, SortMode::SizeAsc, SortMode::SizeDesc] {
        for search in ["", "folder-", "file-"] {
            assert_eq!(before::rows(&entries, search, sort), after::rows(&entries, search, sort));
        }
    }
    let mut old = Vec::new();
    let mut new = Vec::new();
    for _ in 0..7 {
        old.push(before::measure(&entries));
        new.push(after::measure(&entries));
    }
    old.sort(); new.sort();
    println!("20,000 entries / 5,000 root folders; seven runs, median");
    println!("baseline: {} us; current: {} us; speedup: {:.2}x", old[3], new[3], old[3] as f64 / new[3] as f64);
    println!("All four sort orders and three queries produce identical rows.");
}
'''
with tempfile.TemporaryDirectory(prefix='filesec-browser-bench-') as directory:
    source = pathlib.Path(directory) / 'bench.rs'
    binary = pathlib.Path(directory) / 'bench'
    source.write_text(program)
    subprocess.run(['rustc', '--edition=2021', '-O', str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)

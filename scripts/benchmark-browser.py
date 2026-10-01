#!/usr/bin/env python3
"""Benchmark actual browser helpers against a Git revision (default: HEAD).

Runs Rust-optimized microbenchmarks of row preparation and of the trash model
(the trash-heavy case from audit O-01), not disk I/O or painting.
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


def trash_module(name, source):
    signatures = ['struct TrashItem', 'fn pct_decode_seg(', 'fn parse_trash_token(',
                  'fn trashed_subtree_totals(', 'fn trashed_items(']
    body = '\n'.join(item(source, signature) for signature in signatures)
    return 'mod ' + name + '_trash { #![allow(dead_code)] use super::*;\n' + body + r'''
    pub fn items(entries: &[(String, EntryKind, u64)]) -> Vec<(String, String, i64, usize, u64)> {
        trashed_items(entries).into_iter()
            .map(|t| (t.trashed_path, t.orig_path, t.deleted_at, t.files, t.size)).collect()
    }
    pub fn measure(entries: &[(String, EntryKind, u64)]) -> u128 {
        let start = std::time::Instant::now();
        std::hint::black_box(trashed_items(std::hint::black_box(entries)));
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
const TRASH_DIR: &str = ".trash";
use std::collections::HashMap;
fn parent_dir(path: &str) -> &str { match path.rsplit_once('/') { Some((p, _)) => p, None => "" } }
'''
program += module('before', baseline) + module('after', current)
program += trash_module('before', baseline) + trash_module('after', current)
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

    // Trash-heavy model preparation (O-01): every trashed entry is a folder
    // holding one file, plus a live tree of the same size.
    for &dirs in &[1_000usize, 5_000, 10_000, 20_000] {
        let mut entries = Vec::new();
        entries.push((".trash".to_string(), EntryKind::Dir, 0));
        for i in 0..dirs {
            let top = format!(".trash/{}-abcd1234-folder%2Fsub-{i}", 1_700_000_000 + i);
            entries.push((format!("{top}/doc-{i}.txt"), EntryKind::File, i as u64));
            entries.push((top, EntryKind::Dir, 0));
            entries.push((format!("live-{i}.txt"), EntryKind::File, 1));
        }
        assert_eq!(before_trash::items(&entries), after_trash::items(&entries));
        let mut old = Vec::new();
        let mut new = Vec::new();
        for _ in 0..3 {
            old.push(before_trash::measure(&entries));
            new.push(after_trash::measure(&entries));
        }
        old.sort(); new.sort();
        println!(
            "trash model, {} entries / {dirs} trashed folders: baseline {} us; current {} us",
            entries.len(), old[1], new[1]
        );
    }
    println!("The trash model produces identical items (counts and sizes checked).");
}
'''
with tempfile.TemporaryDirectory(prefix='filesec-browser-bench-') as directory:
    source = pathlib.Path(directory) / 'bench.rs'
    binary = pathlib.Path(directory) / 'bench'
    source.write_text(program)
    subprocess.run(['rustc', '--edition=2021', '-O', str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)

#!/usr/bin/env python3
"""Offline, redacted Gitleaks audit of every reachable Git object and history.

Supply an independently verified scanner binary and its expected SHA-256. This
command never downloads tools, sends source to a provider, or prints matches.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

MAX_OBJECT_BYTES = 16 << 20
MAX_TOTAL_BYTES = 256 << 20
MAX_OBJECTS = 200000
HEX = re.compile(r'[a-f0-9]{40}|[a-f0-9]{64}')


class AuditRefused(RuntimeError):
    pass


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise AuditRefused(reason)


def isolated_environment() -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items()
                   if not key.upper().startswith(('GIT_', 'GITLEAKS_'))}
    environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
        GIT_TERMINAL_PROMPT='0', GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1',
        GIT_CONFIG_COUNT='2', GIT_CONFIG_KEY_0='core.hooksPath', GIT_CONFIG_VALUE_0=os.devnull,
        GIT_CONFIG_KEY_1='core.fsmonitor', GIT_CONFIG_VALUE_1='false')
    return environment


def git(repo: Path, *args: str, data: bytes | None = None) -> bytes:
    result = subprocess.run(['git', '--no-replace-objects', '--no-lazy-fetch', '-C', str(repo), *args],
                            input=data, env=isolated_environment(), capture_output=True, timeout=90)
    need(result.returncode == 0, 'Git evidence could not be read; audit is incomplete')
    return result.stdout


def inventory(repo: Path) -> dict:
    common = Path(git(repo, 'rev-parse', '--path-format=absolute', '--git-common-dir').decode().strip())
    own = Path(git(repo, 'rev-parse', '--path-format=absolute', '--git-dir').decode().strip())
    for directory in {common, own}:
        for relative in ('info/grafts', 'objects/info/alternates', 'objects/info/http-alternates'):
            need(not os.path.lexists(directory / relative),
                 'Grafts or alternate object stores require separate complete-history verification')
    need(git(repo, 'rev-parse', '--is-shallow-repository').strip() == b'false',
         'Shallow history cannot establish publication coverage')
    head = git(repo, 'rev-parse', 'HEAD').decode().strip()
    need(bool(HEX.fullmatch(head)), 'A committed HEAD is required')
    refs = git(repo, 'for-each-ref', '--format=%(refname) %(objectname)').decode().splitlines()
    names = git(repo, 'rev-list', '--objects', '--all', 'HEAD').splitlines()
    need(0 < len(names) <= MAX_OBJECTS, 'Object inventory is empty or exceeds its bound')
    identifiers = []
    paths = {}
    for row in names:
        identifier, _, path = row.partition(b' ')
        name = identifier.decode('ascii')
        need(bool(HEX.fullmatch(name)) and name not in paths, 'Object inventory is malformed')
        identifiers.append(name)
        paths[name] = path.decode('utf-8', errors='strict') if path else '<git-metadata>'
    sizes = git(repo, 'cat-file', '--batch-check', data=('\n'.join(identifiers) + '\n').encode()).splitlines()
    need(len(sizes) == len(identifiers), 'Object size inventory is incomplete')
    total = 0
    for expected, row in zip(identifiers, sizes):
        identifier, kind, size_text = row.decode().split()
        size = int(size_text)
        need(identifier == expected and kind in {'commit', 'tree', 'blob', 'tag'} and 0 <= size <= MAX_OBJECT_BYTES,
             'An object exceeds the audit limit or has an unsupported type')
        total += size
        need(total <= MAX_TOTAL_BYTES, 'Reachable object bytes exceed the audit limit')
    raw = git(repo, 'cat-file', '--batch', data=('\n'.join(identifiers) + '\n').encode())
    position = 0
    objects = {}
    counts = Counter()
    for expected in identifiers:
        end = raw.index(b'\n', position)
        identifier, kind, size_text = raw[position:end].decode().split()
        size = int(size_text)
        need(identifier == expected and 0 <= size <= MAX_OBJECT_BYTES, 'Object content inventory changed')
        position = end + 1
        body = raw[position:position + size]
        position += size
        need(raw[position:position + 1] == b'\n', 'Object content is truncated')
        position += 1
        if kind == 'blob':
            need(not re.match(rb'version https://git-lfs\.github\.com/spec/v1\r?\n', body),
                 'Git LFS content requires a separate artifact audit')
        if kind == 'tree':
            # A gitlink records another repository, which this audit cannot read.
            cursor = 0
            while cursor < len(body):
                separator = body.index(b' ', cursor)
                terminator = body.index(b'\0', separator)
                need(body[cursor:separator] != b'160000', 'Submodule contents require a separate repository audit')
                cursor = terminator + 1 + len(identifier) // 2
            need(cursor == len(body), 'Tree representation is malformed')
        counts[kind] += 1
        objects[identifier] = {'kind': kind, 'path': paths[identifier], 'data': body,
                               'sha256': hashlib.sha256(body).hexdigest()}
    need(position == len(raw), 'Unexpected data follows the object inventory')
    return {'head': head, 'refs': refs, 'counts': dict(counts), 'bytes': total, 'objects': objects}


def reviews(path: Path | None) -> dict:
    if path is None:
        return {}
    raw = path.read_bytes()
    need(len(raw) <= 1 << 20, 'Fixture review exceeds its bound')
    rows = json.loads(raw)
    need(isinstance(rows, list) and len(rows) <= 200, 'Fixture review list is invalid')
    result = {}
    for row in rows:
        need(isinstance(row, dict) and set(row) == {'path', 'blobSha256', 'rule', 'line', 'reason'},
             'Fixture reviews must identify exact bytes, rule and line')
        need(row['rule'] == 'generic-api-key' and re.fullmatch('[a-f0-9]{64}', row['blobSha256'])
             and isinstance(row['path'], str) and bool(row['path']) and type(row['line']) is int
             and row['line'] > 0 and isinstance(row['reason'], str) and len(row['reason']) >= 20,
             'Fixture review is not narrow enough')
        key = (row['blobSha256'], row['rule'], row['line'])
        need(key not in result, 'Duplicate fixture review')
        result[key] = row
    return result


def scanner(executable: Path, expected_sha256: str, source: Path, mode: str,
            temporary: Path) -> list[dict]:
    need(bool(re.fullmatch('[a-f0-9]{64}', expected_sha256)) and executable.is_file()
         and not executable.is_symlink() and executable.stat().st_size <= 64 << 20,
         'A verified bounded scanner executable is required')
    need(hashlib.sha256(executable.read_bytes()).hexdigest() == expected_sha256,
         'Scanner executable differs from its reviewed digest')
    config = temporary / 'independent.toml'
    config.write_text('[extend]\nuseDefault = true\n', encoding='utf-8')
    ignore = temporary / 'empty-ignore'
    ignore.write_bytes(b'')
    report = temporary / (mode + '-redacted.json')
    arguments = [str(executable), mode, str(source), '--config', str(config),
        '--gitleaks-ignore-path', str(ignore), '--ignore-gitleaks-allow', '--redact=100',
        '--max-decode-depth=5', '--max-archive-depth=3', '--max-target-megabytes=16',
        '--timeout=180', '--no-banner', '--no-color', '--report-format=json', '--report-path', str(report)]
    if mode == 'git':
        arguments += ['--log-opts=--all --full-history --no-ext-diff --no-textconv HEAD']
    environment = isolated_environment()
    result = subprocess.run(arguments, env=environment, capture_output=True, timeout=200)
    need(result.returncode in (0, 1) and report.is_file(), 'Scanner unavailable or incomplete; no clearance issued')
    need(report.stat().st_size <= 16 << 20, 'Scanner report exceeds its bound')
    rows = json.loads(report.read_text(encoding='utf-8'))
    need(isinstance(rows, list) and len(rows) <= 10000, 'Scanner report is malformed or unbounded')
    need(all(isinstance(row, dict) and row.get('Secret') == 'REDACTED' for row in rows),
         'Scanner output was not fully redacted')
    return rows


def audit(repo: Path, executable: Path, expected_sha256: str, review_file: Path | None = None) -> dict:
    data = inventory(repo)
    reviewed = reviews(review_file)
    findings = {}
    accepted = {}
    with tempfile.TemporaryDirectory(prefix='doxentriq-history-audit-') as name:
        temporary = Path(name)
        objects_root = temporary / 'objects'
        objects_root.mkdir()
        for identifier, item in data['objects'].items():
            if item['kind'] != 'tree':
                (objects_root / identifier).write_bytes(item['data'])
        for mode, source in [('git', repo), ('dir', objects_root)]:
            for row in scanner(executable, expected_sha256, source, mode, temporary):
                line, rule = row.get('StartLine'), row.get('RuleID')
                need(type(line) is int and line > 0 and isinstance(rule, str), 'Invalid finding location')
                if mode == 'dir':
                    identifier = Path(row['File']).name
                    need(identifier in data['objects'], 'Scanner finding escaped the object snapshot')
                    path = data['objects'][identifier]['path']
                else:
                    commit, path = row.get('Commit'), row.get('File')
                    need(isinstance(commit, str) and bool(HEX.fullmatch(commit)) and commit in data['objects']
                         and data['objects'][commit]['kind'] == 'commit' and isinstance(path, str),
                         'Scanner finding escaped reachable history')
                    identifier = git(repo, 'rev-parse', commit + ':' + path).decode().strip()
                    need(identifier in data['objects'], 'Finding object is outside the complete inventory')
                item = data['objects'][identifier]
                key = (item['sha256'], rule, line)
                evidence = {'path': path, 'objectId': identifier, 'objectType': item['kind'],
                            'blobSha256': item['sha256'], 'rule': rule, 'line': line}
                review = reviewed.get(key)
                if review and item['kind'] == 'blob' and review['path'] == path:
                    accepted[key] = evidence | {'reason': review['reason']}
                else:
                    findings[key] = evidence
    need(git(repo, 'rev-parse', 'HEAD').decode().strip() == data['head']
         and git(repo, 'for-each-ref', '--format=%(refname) %(objectname)').decode().splitlines() == data['refs'],
         'Git refs changed during the scan; refresh the evidence before publication')
    return {'schemaVersion': 1, 'ready': not findings, 'head': data['head'], 'refs': data['refs'],
        'objectCounts': data['counts'], 'objectBytes': data['bytes'],
        'scannerBinarySha256': expected_sha256, 'scannedHistoryAndCompleteObjects': True,
        'replacementObjectsIgnored': True, 'lazyObjectFetchingDisabled': True,
        'reviewedFixtureCount': len(accepted), 'reviewedFixtures': list(accepted.values()),
        'findingCount': len(findings), 'findings': list(findings.values()),
        'limitations': 'Reachable local Git refs and HEAD only. Refresh all public refs first; separately audit hosted logs/artifacts, current credential equality, deleted refs, forks and external copies.'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--gitleaks', type=Path, required=True)
    parser.add_argument('--gitleaks-sha256', required=True)
    parser.add_argument('--reviewed-fixtures', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = audit(args.repo.resolve(), args.gitleaks.resolve(), args.gitleaks_sha256, args.reviewed_fixtures)
    except (OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError, AuditRefused):
        print(json.dumps({'ready': False, 'error': 'History audit incomplete; no clearance issued. No source or credential contents are printed.'}))
        return 2
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: value for key, value in report.items() if key not in {'findings', 'reviewedFixtures'}}, indent=2))
    return 0 if report['ready'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Offline publication hygiene check. Never prints matching file contents."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys

MAX_FILE_BYTES = 8 * 1024 * 1024
SKIP_DIRECTORIES = {'.git', '.local', '.local-data', '.cache', 'node_modules', '__pycache__', 'dist', 'coverage'}
PRIVATE_SUFFIXES = {'.key', '.pem', '.ppk', '.p12', '.pfx', '.luks', '.db', '.sqlite', '.sqlite3', '.log', '.dump', '.bak', '.tar', '.gz', '.zip'}
SECRET_PATTERNS = (
    ('private_key', re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\r\n]{64,}')),
    ('provider_credential', re.compile(rb'\bsk-(?:proj-|ant-api\d{2}-)[A-Za-z0-9_-]{30,}')),
    ('github_credential', re.compile(rb'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})')),
    ('aws_access_key', re.compile(rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')),
    ('credential_url', re.compile(rb'(?i)\b(?:https?|mysql|amqps?|rediss?)://[^\s/:@"\x27]{1,100}:[^\s/@"\x27]{8,}@')),
)
LOCAL_PATTERNS = (
    ('operator_home_path', re.compile(rb'(?i)(?:[A-Z]:[/\\]Users[/\\](?!Public\b|Default\b|example\b|USER\b)[A-Za-z0-9_.-]+|/home/(?!example\b|user\b)[A-Za-z0-9_.-]+)')),
    ('trial_endpoint', re.compile(rb'(?i)\b(?:[a-z0-9-]+\.)*fixture\.internal\b')),
)


def candidates(root: Path, tracked_only: bool = False) -> list[str]:
    if (root / '.git').exists():
        args = ['git', '-C', str(root), 'ls-files', '-z', '--cached']
        if not tracked_only:
            args += ['--others', '--exclude-standard']
        result = subprocess.run(args, check=True, capture_output=True, timeout=60)
        return sorted(set(p.decode('utf-8', errors='strict') for p in result.stdout.split(b'\0') if p))
    if tracked_only:
        raise ValueError('--tracked-only requires a Git checkout')
    result = []
    for base, dirs, files in os.walk(root, followlinks=False):
        for name in dirs[:]:
            item = Path(base) / name
            if item.is_symlink() or (getattr(item.lstat(), 'st_file_attributes', 0) & 0x400):
                result.append(item.relative_to(root).as_posix())
                dirs.remove(name)
            elif name in SKIP_DIRECTORIES:
                dirs.remove(name)
        result.extend((Path(base) / name).relative_to(root).as_posix() for name in files)
    return sorted(result)


def inspect(root: Path, paths: list[str]) -> dict:
    root = root.resolve()
    findings = []
    scanned = 0
    content_hashes = {}

    def finding(path: str, code: str, line: int | None = None):
        value = {'path': path, 'code': code}
        if line is not None:
            value['line'] = line
        findings.append(value)

    licenses = {'LICENSE', 'LICENSE.md', 'LICENSE.txt', 'COPYING'}
    if not licenses.intersection(paths):
        finding('.', 'license_missing')
    for relative in sorted(set(paths)):
        pure = PurePosixPath(relative)
        if pure.is_absolute() or '..' in pure.parts or '\\' in relative or ':' in relative:
            finding(relative, 'unsafe_path')
            continue
        path = root.joinpath(*pure.parts)
        try:
            # Reject links in every component before opening the candidate.
            current = root
            for part in pure.parts:
                current /= part
                mode = current.lstat().st_mode
                if stat.S_ISLNK(mode) or (getattr(current.lstat(), 'st_file_attributes', 0) & 0x400):
                    raise ValueError('link')
            if not stat.S_ISREG(mode):
                raise ValueError('special')
        except (OSError, ValueError):
            finding(relative, 'unreadable_or_linked_file')
            continue
        if any(part in SKIP_DIRECTORIES | {'secrets', '.aws', 'backups', 'restores'} for part in pure.parts):
            finding(relative, 'private_directory')
            continue
        if relative.startswith(('deploy/verification/', 'deploy/releases/')):
            finding(relative, 'installation_evidence_or_release_artifact')
            continue
        if path.suffix.lower() in PRIVATE_SUFFIXES or (path.name.startswith('.env') and path.name != '.env.example'):
            finding(relative, 'private_or_generated_file')
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            finding(relative, 'oversized_unreviewed_file')
            continue
        try:
            with path.open('rb') as source:
                data = source.read(MAX_FILE_BYTES + 1)
        except OSError:
            finding(relative, 'unreadable_or_linked_file')
            continue
        if len(data) > MAX_FILE_BYTES:
            finding(relative, 'oversized_unreviewed_file')
            continue
        scanned += 1
        content_hashes[relative] = hashlib.sha256(data).hexdigest()
        for code, pattern in SECRET_PATTERNS:
            match = pattern.search(data)
            if match:
                finding(relative, code, data[:match.start()].count(b'\n') + 1)
        # Synthetic tests may intentionally use local sample endpoints, but even
        # test files must pass credential checks above.
        is_test = any(part in {'test', 'tests'} for part in pure.parts) or path.name.startswith(('test-', 'test_')) or '.test.' in path.name or path.name.endswith('_test.go')
        if not is_test:
            for code, pattern in LOCAL_PATTERNS:
                match = pattern.search(data)
                if match:
                    finding(relative, code, data[:match.start()].count(b'\n') + 1)
    reviewed = []
    review_name = 'scripts/public-release-reviewed-fixtures.json'
    if review_name in content_hashes:
        try:
            reviews = json.loads((root / review_name).read_text(encoding='utf-8'))
            if not isinstance(reviews, list) or len(reviews) > 100:
                raise ValueError('Invalid review list')
            for review in reviews:
                if not isinstance(review, dict) or set(review) != {'path', 'sha256', 'code', 'reason'} or review['code'] not in {'credential_url', 'trial_endpoint'} or not isinstance(review['reason'], str) or not review['reason'].strip() or not re.fullmatch('[a-f0-9]{64}', review['sha256']):
                    raise ValueError('Invalid bounded fixture review')
                if content_hashes.get(review['path']) == review['sha256']:
                    matches = [f for f in findings if f['path'] == review['path'] and f['code'] == review['code']]
                    reviewed.extend(matches)
                    findings = [f for f in findings if f not in matches]
        except (OSError, ValueError, TypeError):
            finding(review_name, 'invalid_fixture_review')
    return {'schemaVersion': 1, 'ready': not findings, 'candidateFiles': len(set(paths)), 'scannedFiles': scanned, 'reviewedFixtureFindings': len(reviewed), 'findingCounts': dict(sorted(Counter(f['code'] for f in findings).items())), 'findings': findings, 'scope': 'Current candidate files only; Git history, dependency licenses, vulnerabilities, installation and usability require separate review.'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--tracked-only', action='store_true', help='Check only tracked files (for CI).')
    parser.add_argument('--report', type=Path, help='Write the full path-only JSON report outside the release candidate.')
    args = parser.parse_args()
    try:
        report = inspect(args.root, candidates(args.root, args.tracked_only))
    except (OSError, ValueError, subprocess.SubprocessError):
        print(json.dumps({'ready': False, 'error': 'Candidate enumeration failed; no publication clearance was issued.'}))
        return 2
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: value for key, value in report.items() if key != 'findings'} | {'sampleFindings': report['findings'][:20]}, indent=2))
    return 0 if report['ready'] else 1


if __name__ == '__main__':
    sys.exit(main())

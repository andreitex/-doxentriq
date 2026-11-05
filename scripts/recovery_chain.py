#!/usr/bin/env python3
"""Trusted recovery inventory validation. This module never touches live data."""
from datetime import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil

CHECKPOINT_ID = re.compile(r'^\d{8}T\d{6}Z-[a-f0-9]{8}$')
DIGEST = re.compile(r'^[a-f0-9]{64}$')
BINLOG = re.compile(r'^mysql-bin\.(\d{6,})$')
MAX_FILES = 1_000_000


def manifest_hash(manifest):
    return hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()


def safe_relative(name):
    if not isinstance(name, str) or len(name) > 1024 or '\\' in name or '\0' in name:
        raise ValueError('Invalid recovery inventory path')
    path = PurePosixPath(name)
    if path.is_absolute() or ':' in name or any(part in {'', '.', '..'} for part in name.split('/')):
        raise ValueError('Recovery inventory must stay in its isolated candidate')
    return path


def inventory(value, documents=False):
    if not isinstance(value, dict) or len(value) > MAX_FILES:
        raise ValueError('Invalid or excessive recovery inventory')
    for name, digest in value.items():
        path = safe_relative(name)
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise ValueError('Recovery file digest is invalid')
        if documents and (len(path.parts) < 5 or path.parts[:2] != ('runtime', 'storage')):
            raise ValueError('Document inventory exceeds app storage scope')
    return value


def binlog_number(name):
    match = BINLOG.fullmatch(name) if isinstance(name, str) else None
    if not match:
        raise ValueError('Invalid recovery binary log name')
    return int(match.group(1))


def contiguous_logs(previous, names):
    if not isinstance(names, list) or len(names) > 100_000:
        raise ValueError('Invalid binary log inventory')
    number = binlog_number(previous)
    for name in names:
        if binlog_number(name) != number + 1:
            raise ValueError('Binary log recovery has a gap or duplicate')
        number += 1
    return names[-1] if names else previous


def checkpoint_time(manifest):
    value = manifest.get('createdAt')
    if not isinstance(value, str) or not value.endswith('Z'):
        raise ValueError('Checkpoint requires an explicit UTC timestamp')
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def protected_recovery_bases(index, cutoff, current_base=None):
    """Keep every ancestor of retained points, including older chain material."""
    if not isinstance(index,dict) or len(index) > 10_000:
        raise ValueError('Recovery retention index is invalid or excessive')
    protected = {current_base} if current_base else set()
    for identifier, item in index.items():
        if not isinstance(identifier,str) or not CHECKPOINT_ID.fullmatch(identifier) or not isinstance(item,dict):
            raise ValueError('Recovery retention entry is invalid')
        base = item.get('baseCheckpointId')
        if not isinstance(base,str) or not CHECKPOINT_ID.fullmatch(base) or item.get('kind') not in {'nightly','incremental'} or item.get('filename') != identifier+'.tar.gpg':
            raise ValueError('Recovery retention has an invalid base or archive')
        if checkpoint_time(item) >= cutoff:
            protected.add(base)
    return protected


def validate_chain(base, increments):
    """Validate exact parent hashes and complete document state at each boundary."""
    if base.get('schemaVersion') != 1 or base.get('kind') != 'nightly' or not CHECKPOINT_ID.fullmatch(base.get('checkpointId', '')):
        raise ValueError('An anchored nightly checkpoint is required')
    files = inventory(base.get('files'))
    recovery = base.get('recoveryBase')
    if not isinstance(recovery, dict):
        raise ValueError('Legacy checkpoint has no verified incremental anchor')
    last_log = recovery.get('binlogFile')
    binlog_number(last_log)
    if files.get('mysql/' + last_log) != recovery.get('binlogSha256'):
        raise ValueError('Nightly binary log anchor differs from the file inventory')
    documents = dict(inventory(recovery.get('documents'), documents=True))
    if documents != {name:digest for name,digest in files.items() if name.startswith('runtime/storage/')}:
        raise ValueError('Nightly document anchor is incomplete')
    previous_id, previous_hash, previous_time = base['checkpointId'], manifest_hash(base), checkpoint_time(base)
    base_hash = previous_hash
    seen, logs = {previous_id}, []
    if not isinstance(increments, list) or len(increments) > 3000:
        raise ValueError('Recovery chain exceeds the 30-day retention bound')
    for item in increments:
        identifier = item.get('checkpointId', '')
        if item.get('schemaVersion') != 1 or item.get('kind') != 'incremental' or not CHECKPOINT_ID.fullmatch(identifier) or identifier in seen:
            raise ValueError('Invalid or duplicated incremental checkpoint')
        if item.get('baseCheckpointId') != base['checkpointId'] or item.get('baseManifestHash') != base_hash or item.get('previousCheckpointId') != previous_id or item.get('previousManifestHash') != previous_hash:
            raise ValueError('Recovery incremental is missing its exact base or parent')
        stamp = checkpoint_time(item)
        if stamp < previous_time:
            raise ValueError('Recovery timestamps are out of order')
        recorded = inventory(item.get('files'))
        closed = item.get('closedBinlogs')
        next_log = contiguous_logs(last_log, closed)
        if item.get('lastClosedBinlog') != next_log:
            raise ValueError('Incremental binary log boundary is inconsistent')
        if {name for name in recorded if name.startswith('mysql/')} != {'mysql/' + name for name in closed}:
            raise ValueError('Incremental binary log files differ from the declared range')
        next_documents = dict(inventory(item.get('documents'), documents=True))
        deleted = item.get('deletedDocuments')
        if not isinstance(deleted, list) or len(deleted) != len(set(deleted)) or set(deleted) != set(documents) - set(next_documents):
            raise ValueError('Incremental document deletions are incomplete or contradictory')
        changed = {name:digest for name,digest in next_documents.items() if documents.get(name) != digest}
        archived_documents = {name:digest for name,digest in recorded.items() if name.startswith('runtime/storage/')}
        if changed != archived_documents:
            raise ValueError('Incremental changed-document inventory is incomplete')
        allowed = all(name.startswith('runtime/storage/') or name.startswith('mysql-keyring/') or name == 'quota/projects.json' or name in {'mysql/' + entry for entry in closed} for name in recorded)
        if not allowed:
            raise ValueError('Incremental includes an unauthorized recovery path')
        documents, last_log = next_documents, next_log
        logs.extend(closed)
        previous_id, previous_hash, previous_time = identifier, manifest_hash(item), stamp
        seen.add(identifier)
    return dict(baseCheckpointId=base['checkpointId'], baseManifestHash=base_hash, targetCheckpointId=previous_id, targetManifestHash=previous_hash, targetTime=previous_time.isoformat(), closedBinlogs=logs, lastClosedBinlog=last_log, documents=documents)


def verify_document_candidate(folder, expected):
    """Check the resulting isolated documents without modifying production."""
    folder = Path(folder)
    actual = {}
    storage = folder / 'runtime/storage'
    for path in storage.rglob('*'):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise ValueError('Recovery documents contain linked or special files')
        if path.is_file():
            digest = hashlib.sha256()
            with path.open('rb') as handle:
                while chunk := handle.read(1024 * 1024):
                    digest.update(chunk)
            actual[path.relative_to(folder).as_posix()] = digest.hexdigest()
    if actual != expected:
        raise ValueError('Restored document inventory differs from the recovery boundary')


def apply_document_increment(candidate, extracted, manifest):
    """Apply a verified delta only to a separately extracted candidate directory."""
    candidate, extracted = Path(candidate).resolve(strict=True), Path(extracted).resolve(strict=True)
    if candidate == extracted or candidate in extracted.parents or extracted in candidate.parents:
        raise ValueError('Incremental and recovery candidate must be separate')
    for name in manifest['deletedDocuments']:
        target = candidate.joinpath(*safe_relative(name).parts)
        if candidate not in target.resolve().parents:
            raise ValueError('Recovery deletion escapes its isolated candidate')
        if target.is_symlink() or not target.is_file():
            raise ValueError('Expected recovery document is missing or linked')
        target.unlink()
    for name in manifest['files']:
        if name.startswith('runtime/storage/'):
            source = extracted.joinpath(*safe_relative(name).parts)
            target = candidate.joinpath(*safe_relative(name).parts)
            if extracted not in source.resolve(strict=True).parents or candidate not in target.resolve().parents or source.is_symlink() or not source.is_file():
                raise ValueError('Recovery file escapes the validated archive')
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
    verify_document_candidate(candidate, manifest['documents'])

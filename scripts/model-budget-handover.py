#!/usr/bin/env python3
"""Company-only, one-way handover of an existing monthly testing allowance.

This command makes no provider calls. It first prevents any more company tests,
then exports the exact remaining allowance for a previously unused workflow ledger.
No refund, reset, automatic renewal or second allocation is supported.
"""
from datetime import datetime
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import uuid
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo


def module():
    spec = importlib.util.spec_from_file_location('budget', Path(__file__).with_name('model-test-budget.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def prepare(m, ledger, before_hash, origin, month):
    m.require_clear_ledger(ledger)
    url = urlsplit(origin)
    if (url.scheme != 'https' or not url.hostname or url.username or url.password or
            url.path or url.query or url.fragment or not re.fullmatch(r'[0-9a-f]{64}', before_hash) or
            not re.fullmatch(r'\d{4}-(0[1-9]|1[0-2])', month)):
        raise ValueError('Exact HTTPS origin, ledger hash and accounting month required')
    hostname = '[' + url.hostname + ']' if ':' in url.hostname else url.hostname
    canonical = 'https://' + hostname + (':' + str(url.port) if url.port and url.port != 443 else '')
    if origin != canonical or not hostname.isascii():
        raise ValueError('A canonical HTTPS administrator origin is required')
    totals = m.accounting(ledger, month)
    remaining = ledger['monthlyLimitMicrousd'] - totals['confirmedMicrousd'] - totals['conservativeMicrousd']
    if remaining <= 0:
        raise ValueError('No remaining allowance to hand over')
    return dict(schemaVersion=1, id=uuid.uuid4().hex, month=month, timezone=ledger['timezone'],
                adminOrigin=origin, beforeLedgerSha256=before_hash,
                monthlyLimitMicrousd=ledger['monthlyLimitMicrousd'],
                confirmedExternalMicrousd=totals['confirmedMicrousd'],
                conservativeExternalMicrousd=totals['conservativeMicrousd'], allocationMicrousd=remaining)


def handover(m, directory, expected_hash, monthly_usd, timezone, origin):
    """Caller holds the original monthly lock. Export only after ledger commit.

    A crash before the commit leaves no usable authority. A crash after the
    commit can recover the already committed authority without another debit.
    """
    before = m.private_read(directory, 'monthly.json')
    ledger = json.loads(before)
    m.validate(ledger, monthly_usd, timezone)
    m.verify_conservative_evidence(directory, ledger)
    allocations = [r for r in ledger['runs'] if r['status'] == 'allocated']
    if allocations:
        if len(allocations) != 1:
            raise ValueError('Multiple allocations require company reconciliation')
        run = allocations[0]
        raw = m.private_read(directory, 'allocation-' + run['id'] + '.json')
        authority = json.loads(raw)
        original = m.private_read(directory, 'allocation-' + run['id'] + '.before.json')
        original_ledger = json.loads(original)
        m.validate(original_ledger, monthly_usd, timezone)
        m.verify_conservative_evidence(directory, original_ledger)
        restored = prepare(m, original_ledger, expected_hash, origin, run['month'])
        restored['id'] = run['id']
        if (authority != restored or hashlib.sha256(original).hexdigest() != expected_hash or
                hashlib.sha256(raw).hexdigest() != run['reportSha256'] or
                run['reservedMicrousd'] != authority['allocationMicrousd']):
            raise ValueError('The committed handover evidence changed')
        return authority
    if hashlib.sha256(before).hexdigest() != expected_hash:
        raise ValueError('Ledger changed after review; no handover performed')
    month = datetime.now(ZoneInfo(timezone)).strftime('%Y-%m')
    authority = prepare(m, ledger, expected_hash, origin, month)
    name = 'allocation-' + authority['id']
    # Fresh identifiers and exclusive creation preserve every pre-handover byte.
    fd = os.open(name + '.before.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as out:
            out.write(before)
            out.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory)
    evidence_hash = m.durable_json(directory, name + '.json', authority)
    ledger['runs'].append(dict(id=authority['id'], month=month, reservedMicrousd=authority['allocationMicrousd'],
                              spentMicrousd=0, status='allocated', createdAt=datetime.now().astimezone().isoformat(), reportSha256=evidence_hash))
    m.validate(ledger, monthly_usd, timezone)
    m.durable_json(directory, 'monthly.json', ledger)
    return authority


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('state-dir', 'expected-ledger-sha256', 'monthly-max-usd', 'admin-origin'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--timezone', default='Europe/Bucharest')
    config = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('Company root invocation required')
    m = module()
    directory = m.open_private_directory(config.state_dir)
    try:
        lock = os.open('monthly.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            row = os.fstat(lock)
            if not stat.S_ISREG(row.st_mode) or row.st_uid != 0 or row.st_nlink != 1 or stat.S_IMODE(row.st_mode) != 0o600:
                raise ValueError('Original protected company lock required')
            m.fcntl.flock(lock, m.fcntl.LOCK_EX | m.fcntl.LOCK_NB)
            authority = handover(m, directory, config.expected_ledger_sha256, config.monthly_max_usd, config.timezone, config.admin_origin)
            # This is the ONLY exported grant; pre-commit files are audit evidence.
            # Persist this bounded nonsecret result as company-controlled read-only
            # configuration. Never mount the company journal into an application.
            print(json.dumps(authority, allow_nan=False))
        finally:
            os.close(lock)
    finally:
        os.close(directory)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps(dict(errorCode='budget_handover_stopped', error='No additional allowance granted; inspect protected handover evidence.')))
        raise SystemExit(1)

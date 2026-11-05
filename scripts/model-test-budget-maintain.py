#!/usr/bin/env python3
"""Explicit company maintenance of testing limits; never calls model providers.

No reset, refund or invoice-guessing operation exists. Full-reservation accounting
requires separate owner approval and retains the original unknown billing report.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import uuid


def module():
    spec = importlib.util.spec_from_file_location('budget', Path(__file__).with_name('model-test-budget.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['amend-limit', 'account-maximum'])
    parser.add_argument('--state-dir', required=True)
    parser.add_argument('--expected-ledger-sha256', required=True)
    parser.add_argument('--monthly-max-usd', required=True)
    parser.add_argument('--timezone', default='Europe/Bucharest')
    parser.add_argument('--new-monthly-max-usd')
    parser.add_argument('--run-id')
    parser.add_argument('--expected-report-sha256')
    parser.add_argument('--confirm-owner-approved-full-reservation', action='store_true')
    config = parser.parse_args()
    if os.geteuid() != 0 or not re.fullmatch(r'[0-9a-f]{64}', config.expected_ledger_sha256):
        raise ValueError('Company root and exact reviewed ledger hash required')
    m = module()
    directory = m.open_private_directory(config.state_dir)
    lock = os.open('monthly.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        row = os.fstat(lock)
        if not stat.S_ISREG(row.st_mode) or row.st_uid != 0 or row.st_nlink != 1 or stat.S_IMODE(row.st_mode) != 0o600:
            raise ValueError('Original private monthly lock required')
        m.fcntl.flock(lock, m.fcntl.LOCK_EX | m.fcntl.LOCK_NB)
        before = m.private_read(directory, 'monthly.json')
        if hashlib.sha256(before).hexdigest() != config.expected_ledger_sha256:
            raise ValueError('Ledger changed after review; no amendment applied')
        ledger = json.loads(before)
        m.validate(ledger, config.monthly_max_usd, config.timezone)
        m.verify_conservative_evidence(directory, ledger)
        evidence = dict(schemaVersion=1, checkedAt=datetime.now(timezone.utc).isoformat(),
                        beforeLedgerSha256=config.expected_ledger_sha256, modelRequests=0)
        if config.action == 'amend-limit':
            if not config.new_monthly_max_usd or config.run_id or config.expected_report_sha256 or config.confirm_owner_approved_full_reservation:
                raise ValueError('Limit amendment cannot resolve any billing hold')
            changed = m.amend_limit(ledger, config.monthly_max_usd, config.new_monthly_max_usd, config.timezone)
            evidence.update(kind='company-testing-limit-amendment-v1',
                            oldLimitMicrousd=ledger['monthlyLimitMicrousd'], newLimitMicrousd=changed['monthlyLimitMicrousd'],
                            historicalRunsUnchanged=changed['runs'] == ledger['runs'])
            name = 'limit-amendment-' + uuid.uuid4().hex
        else:
            if (config.new_monthly_max_usd or not config.confirm_owner_approved_full_reservation or
                    not config.run_id or not re.fullmatch(r'[0-9a-f]{32}', config.run_id)):
                raise ValueError('Separate owner approval to account the full reservation is required')
            if not config.expected_report_sha256 or not re.fullmatch(r'[0-9a-f]{64}', config.expected_report_sha256):
                raise ValueError('Exact reviewed original report hash required')
            matches = [r for r in ledger['runs'] if r['id'] == config.run_id]
            if len(matches) != 1 or matches[0]['status'] != 'held':
                raise ValueError('Exact unresolved run required')
            unit = 'autosoft-model-test-' + config.run_id + '.service'
            result = subprocess.run(['/usr/bin/systemctl', 'show', unit, '--property=ActiveState,SubState,MainPID,ControlPID'],
                                    capture_output=True, timeout=15, env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
            observed = dict(line.split('=', 1) for line in result.stdout.decode('ascii').splitlines() if '=' in line)
            if observed.get('ActiveState') not in ('inactive', 'failed') or observed.get('MainPID') != '0' or observed.get('ControlPID') != '0':
                raise ValueError('Original test service termination cannot be confirmed')
            original_report = m.private_read(directory, config.run_id + '.report.json')
            if hashlib.sha256(original_report).hexdigest() != config.expected_report_sha256:
                raise ValueError('Original billing report changed after review')
            evidence.update(kind='company-full-reservation-accounting-v1', runId=config.run_id,
                            budgetDebitMicrousd=matches[0]['reservedMicrousd'], providerBillingConfirmed=False,
                            ownerApprovedFullReservation=True, serviceEnded=True, serviceObservation=observed,
                            originalReportSha256=hashlib.sha256(original_report).hexdigest())
            name = 'conservative-' + config.run_id
        # Fresh durable evidence precedes the only mutable ledger replacement.
        # A crash can leave unconsumed evidence; reruns never overwrite it.
        for target in (name + '.json', name + '.before.json'):
            try:
                os.stat(target, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError('Maintenance evidence already exists; inspect before retrying')
        before_name = name + '.before.json'
        fd = os.open(before_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as output:
                output.write(before)
                output.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(directory)
        evidence_hash = m.durable_json(directory, name + '.json', evidence)
        if config.action == 'account-maximum':
            changed = m.account_maximum(ledger, config.run_id, evidence_hash)
            m.verify_conservative_evidence(directory, changed)
        m.durable_json(directory, 'monthly.json', changed)
        print(json.dumps(dict(action=config.action, monthlyLimitUsd=changed['monthlyLimitMicrousd']/1e6,
                              heldRuns=sum(r['status']=='held' for r in changed['runs']),
                              conservativeRuns=sum(r['status']=='conservative' for r in changed['runs']),
                              evidence=name+'.json', modelRequests=0)))
    finally:
        os.close(lock)
        os.close(directory)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps(dict(errorCode='budget_maintenance_stopped', error='No testing admission granted; inspect the protected ledger and maintenance evidence.')))
        raise SystemExit(1)

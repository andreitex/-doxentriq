#!/usr/bin/env python3
"""Company-only model qualification with a durable, fail-closed monthly ledger.

Runs trusted company JavaScript as a transient unprivileged systemd service.
This is not an application build runner or the production workflow ledger.
"""
import argparse
from copy import deepcopy
from datetime import datetime
from decimal import Decimal, InvalidOperation, ROUND_CEILING
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import uuid
from zoneinfo import ZoneInfo

MICRO = Decimal(1000000)


class UncertainBillingError(ValueError):
    pass


def require_clear_ledger(ledger):
    if any(run['status'] == 'allocated' for run in ledger['runs']):
        raise ValueError('The allowance was handed over to platform workflows; company model tests are disabled')
    if any(run['status'] not in ('settled', 'conservative') for run in ledger['runs']):
        raise UncertainBillingError('An earlier test has uncertain billing; reconcile before another run')


def accounting(ledger, month):
    runs = [run for run in ledger['runs'] if run['month'] == month]
    return dict(confirmedMicrousd=sum(r['spentMicrousd'] for r in runs if r['status'] == 'settled'),
                conservativeMicrousd=sum(r['spentMicrousd'] for r in runs if r['status'] == 'conservative'),
                heldMicrousd=sum(r['reservedMicrousd'] for r in ledger['runs'] if r['status'] == 'held'),
                allocatedMicrousd=sum(r['reservedMicrousd'] for r in runs if r['status'] == 'allocated'))


def amend_limit(ledger, old_usd, new_usd, timezone):
    """An explicit company amendment preserves every prior run and unknown outcome."""
    validate(ledger, old_usd, timezone)
    result = deepcopy(ledger)
    maximum = units(new_usd)
    if maximum <= 0 or maximum == result['monthlyLimitMicrousd']:
        raise ValueError('A different positive approved monthly limit is required')
    months = {run['month'] for run in result['runs']}
    for month in months:
        committed = sum(r['spentMicrousd'] if r['status'] not in ('held', 'allocated') else r['reservedMicrousd']
                        for r in result['runs'] if r['month'] == month)
        if committed > maximum:
            raise ValueError('The amended limit cannot exclude already committed testing costs')
    result['monthlyLimitMicrousd'] = maximum
    validate(result, new_usd, timezone)
    return result


def account_maximum(ledger, run_id, evidence_hash):
    """Company-approved full budget debit; never a claim about the provider invoice.

    The caller retains the original ledger/report, records explicit authorization,
    confirms the original service has ended, and durably stores its audit evidence
    before publishing this result. No refund or replay operation is provided.
    """
    validate(ledger, str(Decimal(ledger['monthlyLimitMicrousd']) / MICRO), ledger['timezone'])
    if not re.fullmatch(r'[0-9a-f]{64}', evidence_hash):
        raise ValueError('Exact conservative accounting evidence required')
    result = deepcopy(ledger)
    matches = [run for run in result['runs'] if run['id'] == run_id]
    if len(matches) != 1 or matches[0]['status'] != 'held':
        raise ValueError('An exact unresolved run is required; no accounting replay allowed')
    matches[0].update(status='conservative', spentMicrousd=matches[0]['reservedMicrousd'], reportSha256=evidence_hash)
    return result


def units(value):
    try:
        number = Decimal(str(value))
        if not number.is_finite() or number < 0 or number > 1000000:
            raise ValueError('Invalid dollar amount')
        return int((number * MICRO).to_integral_value(rounding=ROUND_CEILING))
    except InvalidOperation:
        raise ValueError('Invalid dollar amount') from None


def new_ledger(monthly_usd, timezone):
    maximum = units(monthly_usd)
    if maximum <= 0:
        raise ValueError('Positive monthly budget required')
    ZoneInfo(timezone)
    return dict(schemaVersion=1, monthlyLimitMicrousd=maximum, timezone=timezone, runs=[])


def validate(ledger, monthly_usd, timezone):
    if (set(ledger) != {'schemaVersion', 'monthlyLimitMicrousd', 'timezone', 'runs'} or
            ledger['schemaVersion'] != 1 or ledger['monthlyLimitMicrousd'] != units(monthly_usd) or
            ledger['timezone'] != timezone or not isinstance(ledger['runs'], list)):
        raise ValueError('Monthly ledger or approved limit changed; company reconciliation required')
    identifiers = set()
    for run in ledger['runs']:
        if (set(run) != {'id', 'month', 'reservedMicrousd', 'spentMicrousd', 'status', 'createdAt', 'reportSha256'} or
                not re.fullmatch(r'[0-9a-f]{32}', str(run['id'])) or run['id'] in identifiers or
                not re.fullmatch(r'\d{4}-\d{2}', str(run['month'])) or
                run['status'] not in ('held', 'settled', 'conservative', 'allocated') or
                type(run['reservedMicrousd']) is not int or run['reservedMicrousd'] <= 0 or
                type(run['spentMicrousd']) is not int or run['spentMicrousd'] < 0 or
                (run['status'] == 'held' and (run['spentMicrousd'] != 0 or run['reportSha256'] is not None)) or
                (run['status'] in ('settled', 'conservative', 'allocated') and not re.fullmatch(r'[0-9a-f]{64}', str(run['reportSha256']))) or
                (run['status'] == 'allocated' and run['spentMicrousd'] != 0) or
                (run['status'] == 'conservative' and run['spentMicrousd'] != run['reservedMicrousd'])):
            raise ValueError('Invalid monthly ledger; no provider request allowed')
        identifiers.add(run['id'])


def reserve(ledger, month, run_usd):
    # An unknown previous run blocks even a new month. Never guess whether it billed.
    require_clear_ledger(ledger)
    amount = units(run_usd)
    spent = sum(run['spentMicrousd'] for run in ledger['runs'] if run['month'] == month)
    if amount <= 0 or spent + amount > ledger['monthlyLimitMicrousd']:
        raise ValueError('Monthly testing budget cannot reserve this run; no request sent')
    run = dict(id=uuid.uuid4().hex, month=month, reservedMicrousd=amount,
               spentMicrousd=0, status='held', createdAt=datetime.now().astimezone().isoformat(), reportSha256=None)
    ledger['runs'].append(run)
    return run


def settle(run, report, report_hash, suite_usd, request_usd):
    if (report.get('schemaVersion') != 1 or units(report.get('aggregateLimitUsd')) != run['reservedMicrousd'] or
            units(report.get('perSuiteLimitUsd')) != units(suite_usd) or
            units(report.get('perRequestLimitUsd')) != units(request_usd) or
            report.get('heldUsd') != 0 or not isinstance(report.get('results'), list) or not report['results']):
        raise ValueError('Run billing is uncertain; reservation retained')
    total = Decimal(0)
    for result in report['results']:
        if result.get('heldUsd') != 0 or not isinstance(result.get('cases'), list) or not result['cases']:
            raise ValueError('Incomplete billing evidence; reservation retained')
        actual = units(result.get('spentUsd'))
        for case in result['cases']:
            units(case.get('costUsd'))
        cases = sum((Decimal(str(case.get('costUsd'))) for case in result['cases']), Decimal(0))
        # The JS receipt sums IEEE-754 values; tolerate only sub-picodollar
        # representation noise, never a missing microdollar of billed usage.
        if abs(cases - Decimal(str(result['spentUsd']))) > Decimal('0.000000000001'):
            raise ValueError('Inconsistent case billing; reservation retained')
        total += Decimal(str(result['spentUsd']))
    if abs(total - Decimal(str(report.get('spentUsd')))) > Decimal('0.000000000001'):
        raise ValueError('Inconsistent aggregate billing; reservation retained')
    actual = units(report['spentUsd'])
    # Record even an overrun, then the admission check blocks further spending.
    run.update(status='settled', spentMicrousd=actual, reportSha256=report_hash)


def open_private_directory(path):
    if not os.path.isabs(path) or any(part in ('.', '..', '') for part in path.split('/')[1:]):
        raise ValueError('Absolute canonical state path required')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.split('/')[1:]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = following
            row = os.fstat(descriptor)
            if row.st_uid != 0 or stat.S_IMODE(row.st_mode) & 0o022:
                raise ValueError('State parents must be root-owned without shared write access')
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o700:
            raise ValueError('State directory must have mode 0700')
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def private_read(directory, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1 or
                stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > 2 * 1024 * 1024):
            raise ValueError('Private bounded ledger file required')
        chunks = []
        while True:
            part = os.read(fd, 65536)
            if not part:
                break
            chunks.append(part)
            if sum(map(len, chunks)) > 2 * 1024 * 1024:
                raise ValueError('Ledger size exceeded')
        identity = lambda row: (row.st_dev, row.st_ino, row.st_mode, row.st_uid, row.st_nlink,
                                row.st_size, row.st_mtime_ns, row.st_ctime_ns)
        if identity(os.fstat(fd)) != identity(before):
            raise ValueError('Ledger changed while reading')
        return b''.join(chunks)
    finally:
        os.close(fd)


def trusted_file(path):
    if not os.path.isabs(path) or any(part in ('.', '..', '') for part in path.split('/')[1:]) or any(c in path for c in '\n\r:'):
        raise ValueError('Canonical company tool paths required')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.split('/')[1:-1]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = following
            row = os.fstat(directory)
            if row.st_uid != 0 or stat.S_IMODE(row.st_mode) & 0o022:
                raise ValueError('Company tool parents must be protected and root-owned')
        fd = os.open(path.split('/')[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            row = os.fstat(fd)
            if (not stat.S_ISREG(row.st_mode) or row.st_uid != 0 or row.st_nlink != 1 or
                    stat.S_IMODE(row.st_mode) & 0o022):
                raise ValueError('Company tools must be protected root-owned regular files')
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def durable_json(directory, name, value):
    data = (json.dumps(value, indent=2, allow_nan=False) + '\n').encode()
    temporary = '.write-' + uuid.uuid4().hex
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as output:
            output.write(data)
            output.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
    os.fsync(directory)
    return hashlib.sha256(data).hexdigest()


def verify_conservative_evidence(directory, ledger):
    for run in ledger['runs']:
        if run['status'] != 'conservative':
            continue
        raw = private_read(directory, 'conservative-' + run['id'] + '.json')
        evidence = json.loads(raw)
        before = private_read(directory, 'conservative-' + run['id'] + '.before.json')
        original = json.loads(before)
        old_runs = [r for r in original.get('runs', []) if r.get('id') == run['id']]
        original_report = private_read(directory, run['id'] + '.report.json')
        if (hashlib.sha256(raw).hexdigest() != run['reportSha256'] or
                evidence.get('kind') != 'company-full-reservation-accounting-v1' or
                evidence.get('runId') != run['id'] or
                evidence.get('budgetDebitMicrousd') != run['reservedMicrousd'] or
                evidence.get('providerBillingConfirmed') is not False or
                evidence.get('ownerApprovedFullReservation') is not True or
                evidence.get('serviceEnded') is not True or
                evidence.get('beforeLedgerSha256') != hashlib.sha256(before).hexdigest() or
                evidence.get('originalReportSha256') != hashlib.sha256(original_report).hexdigest() or
                len(old_runs) != 1 or old_runs[0]['status'] != 'held' or
                any(old_runs[0][k] != run[k] for k in ('id', 'month', 'reservedMicrousd', 'createdAt'))):
            raise ValueError('Conservative budget accounting evidence changed; no provider request allowed')


def separate_artifacts(report):
    """Generated source stays in private artifact storage, never diagnostic output."""
    if not isinstance(report, dict):
        raise ValueError('Object report required')
    report = dict(report)
    artifacts = report.pop('artifacts', {})
    if (not isinstance(artifacts, dict) or not set(artifacts).issubset({'dms-candidate.json'}) or
            any(not isinstance(value, dict) for value in artifacts.values()) or
            len(json.dumps(artifacts, allow_nan=False).encode()) > 1024 * 1024):
        raise ValueError('Invalid private candidate artifact')
    return report, artifacts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('state-dir', 'node', 'runner', 'catalog', 'openai-key-file', 'anthropic-key-file'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--monthly-max-usd', required=True)
    parser.add_argument('--max-usd', required=True)
    parser.add_argument('--suite-max-usd', required=True)
    parser.add_argument('--request-max-usd', required=True)
    parser.add_argument('--timezone', default='Europe/Bucharest')
    parser.add_argument('--model', action='append', default=[])
    config = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('Company root invocation required')
    directory = open_private_directory(config.state_dir)
    try:
        lock = os.open('monthly.lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
        fresh_lock = True
    except FileExistsError:
        lock = os.open('monthly.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        fresh_lock = False
    row = os.fstat(lock)
    if not stat.S_ISREG(row.st_mode) or row.st_uid != 0 or row.st_nlink != 1 or stat.S_IMODE(row.st_mode) != 0o600:
        raise ValueError('Private monthly lock required')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.fsync(directory)
    try:
        ledger = json.loads(private_read(directory, 'monthly.json'))
    except FileNotFoundError:
        # A surviving lock is not a fresh-install signal: creation of a missing
        # ledger is permitted only when the directory contains the lock alone.
        if not fresh_lock or set(os.listdir(directory)) != {'monthly.lock'}:
            raise ValueError('Missing monthly ledger in nonempty state; reconciliation required')
        ledger = new_ledger(config.monthly_max_usd, config.timezone)
    validate(ledger, config.monthly_max_usd, config.timezone)
    verify_conservative_evidence(directory, ledger)
    require_clear_ledger(ledger)  # Refuse before loading tools or credentials.
    for path in (config.node, config.runner, config.catalog):
        trusted_file(path)
    source_directory = str(Path(config.runner).parent)
    if any(str(Path(path).parent) != source_directory for path in (config.node, config.catalog)):
        raise ValueError('Company runtime, runner and catalog must share one protected directory')
    spec = importlib.util.spec_from_file_location('preflight', Path(__file__).with_name('provider-preflight.py'))
    preflight = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(preflight)
    keys = {provider: preflight.api_key(preflight.protected_file(getattr(config, provider + '_key_file')), provider)
            for provider in ('openai', 'anthropic')}
    now = datetime.now(ZoneInfo(config.timezone))
    run = reserve(ledger, now.strftime('%Y-%m'), config.max_usd)
    durable_json(directory, 'monthly.json', ledger)  # Before the first possible paid action.
    unit = 'autosoft-model-test-' + run['id']
    mount = '/opt/autosoft-model-test'
    arguments = ['/usr/bin/env', mount + '/' + Path(config.node).name, mount + '/' + Path(config.runner).name,
                 '--catalog', mount + '/' + Path(config.catalog).name, '--max-usd', config.max_usd,
                 '--suite-max-usd', config.suite_max_usd, '--request-max-usd', config.request_max_usd]
    for model in config.model:
        arguments.extend(['--model', model])
    env = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', LANG='C.UTF-8')
    # LoadCredential makes private copies readable only by this DynamicUser.
    # Keys never appear in arguments, the inherited environment, or diagnostics.
    with tempfile.TemporaryDirectory(prefix='autosoft-model-test-', dir='/run') as credentials:
        command = ['/usr/bin/systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--service-type=exec', '--unit=' + unit]
        command.extend(['--property', 'BindReadOnlyPaths=' + source_directory + ':' + mount])
        for setting in ('DynamicUser=yes', 'ProtectSystem=strict', 'ProtectHome=yes', 'PrivateTmp=yes',
                        'PrivateDevices=yes', 'NoNewPrivileges=yes', 'ProtectKernelTunables=yes',
                        'ProtectKernelModules=yes', 'ProtectControlGroups=yes', 'RestrictSUIDSGID=yes',
                        'RestrictRealtime=yes', 'LockPersonality=yes', 'CapabilityBoundingSet=',
                        'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6', 'LimitCORE=0',
                        'MemoryMax=512M', 'CPUQuota=100%', 'TasksMax=24', 'RuntimeMaxSec=2400', 'UMask=0077'):
            command.extend(['--property', setting])
        for provider, key in keys.items():
            target = os.path.join(credentials, provider)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as output:
                output.write(key)
            command.extend(['--property', 'LoadCredential=' + provider + ':' + target,
                            '--setenv', provider.upper() + '_API_KEY_FILE=/run/credentials/' + unit + '.service/' + provider])
        try:
            result = subprocess.run(command + ['--'] + arguments, env=env, capture_output=True, timeout=2460)
        except subprocess.TimeoutExpired:
            subprocess.run(['/usr/bin/systemctl', 'stop', unit], env=env, capture_output=True, timeout=30)
            raise ValueError('Test timed out; monthly reservation retained') from None
    if len(result.stdout) > 2 * 1024 * 1024 or any(key.encode() in result.stdout for key in keys.values()):
        raise ValueError('Invalid test output; monthly reservation retained')
    try:
        report, artifacts = separate_artifacts(json.loads(result.stdout))
        report_hash = durable_json(directory, run['id'] + '.report.json', report)
        settle(run, report, report_hash, config.suite_max_usd, config.request_max_usd)
        for name, artifact in artifacts.items():
            durable_json(directory, run['id'] + '.' + name, artifact)
    except (ValueError, TypeError, KeyError):
        raise ValueError('Test has no complete billing receipt; monthly reservation retained') from None
    durable_json(directory, 'monthly.json', ledger)
    totals = accounting(ledger, run['month'])
    print(json.dumps(dict(runId=run['id'], monthlyLimitUsd=ledger['monthlyLimitMicrousd'] / 1e6,
                          monthlySpentUsd=sum(r['spentMicrousd'] for r in ledger['runs'] if r['month'] == run['month']) / 1e6,
                          monthlyConfirmedUsd=totals['confirmedMicrousd'] / 1e6,
                          monthlyConservativeUsd=totals['conservativeMicrousd'] / 1e6,
                          report=report, childExit=result.returncode)))
    return 0 if result.returncode == 0 else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        # Never echo child diagnostics, parsed credentials or provider bodies.
        print(json.dumps(dict(errorCode='billing_reconciliation_required' if isinstance(error, UncertainBillingError) else 'model_test_stopped',
                              error='Model test stopped; inspect protected ledger and sanitized report before retrying.',
                              mayHaveHeldReservation=True)))
        raise SystemExit(1)

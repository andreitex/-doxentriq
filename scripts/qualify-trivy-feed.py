#!/usr/bin/env python3
"""One-shot isolated OS-feed qualification; native dispatch requires an exact grant.

This is independent of maintenance scanning, release gates and global cache state.
The injectable daemon boundary is deliberately small and never runs a shell.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import threading
import time

VERSION = '0.75.0'
CVE = 'CVE-2023-38545'
VERSIONS = {'vulnerable': '7.88.1-10', 'fixed': '7.88.1-10+deb12u4'}
HASH = re.compile(r'[a-f0-9]{64}')
IMAGE = re.compile(r'[a-zA-Z0-9._:/-]+@sha256:[a-f0-9]{64}')
ROOT = re.compile(r'/srv/autosoft/validation/trivy-isolated-scanner-v1-[a-f0-9]{32}')
FEED = re.compile(r'/srv/autosoft/validation/trivy-feed-stream-v1-[a-f0-9]{32}/data/security-cache/trivy/db')
LIMITS = dict(wholeSeconds=600, activeSeconds=480, cleanupSeconds=120,
              daemonCalls=48, containers=3, stdoutBytes=2*1024**2,
              stderrBytes=65536, evidenceBytes=16*1024**2, evidenceFiles=40,
              memoryBytes=3*1024**3, nanoCpus=2*10**9, pids=64)
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
SCANNER_ARGS = ('rootfs', '--config=', '--ignorefile=', '--pkg-types=os',
                '--list-all-pkgs', '--cache-dir=/cache/trivy', '--cache-backend=memory',
                '--skip-db-update', '--skip-java-db-update', '--offline-scan',
                '--skip-version-check', '--disable-telemetry', '--scanners=vuln',
                '--format=json', '--timeout=2m', '--parallel=1', '/inventory')
TMPFS = {'/cache/trivy': 'size=64m,mode=0700,uid=10001,gid=10001,nosuid,nodev,noexec',
         '/tmp': 'size=128m,mode=1777,nosuid,nodev,noexec'}
UNCERTAIN_NATIVE_OWNERS = []


class Unavailable(ValueError):
    """Only fixed public reason tokens; never external exception text."""


def require(value, code):
    if value is not True:
        raise Unavailable(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def closed(value, keys):
    require(type(value) is dict and set(value) == set(keys), 'closed_schema')


def pin(value, maximum):
    closed(value, ('sha256', 'bytes'))
    require(type(value['sha256']) is str and HASH.fullmatch(value['sha256']) is not None
            and type(value['bytes']) is int and 0 < value['bytes'] <= maximum, 'content_pin')


def parse(raw, maximum=2*1024**2):
    require(type(raw) is bytes and 0 < len(raw) <= maximum, 'json_size')
    def pairs(rows):
        result = {}; aliases = set()
        for key, value in rows:
            require(key.casefold() not in aliases, 'duplicate_json_key')
            aliases.add(key.casefold()); result[key] = value
        return result
    def invalid(_):
        raise Unavailable('nonfinite_json')
    try:
        value = json.loads(raw.decode('utf8', 'strict'), object_pairs_hook=pairs,
                           parse_constant=invalid)
    except Unavailable:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise Unavailable('invalid_json') from None
    def bounded(item, depth=0):
        require(depth <= 24, 'json_depth')
        if type(item) is dict:
            require(len(item) <= 256, 'json_members')
            for key, child in item.items():
                require(len(key) <= 256, 'json_key'); bounded(child, depth+1)
        elif type(item) is list:
            require(len(item) <= 512, 'json_items')
            for child in item: bounded(child, depth+1)
        elif type(item) is str:
            require(len(item) <= 16384, 'json_string')
    bounded(value)
    return value


def instant(value):
    require(type(value) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z', value) is not None, 'utc_format')
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise Unavailable('utc_value') from None


def validate(scope, company, feed, now):
    closed(scope, ('schemaVersion', 'status', 'operationId', 'notBefore', 'expiresAt',
                   'maximumInvocations', 'nativeDispatch', 'root', 'companyEvidence', 'feedEvidence', 'limits'))
    require(type(scope['schemaVersion']) is int and scope['schemaVersion'] == 1
            and scope['status'] == 'root_authorized_isolated_probe_once'
            and type(scope['maximumInvocations']) is int and scope['maximumInvocations'] == 1
            and type(scope['nativeDispatch']) is bool, 'scope_authority')
    require(type(scope['operationId']) is str and re.fullmatch('[a-f0-9]{32}', scope['operationId']) is not None
            and scope['root'] == '/srv/autosoft/validation/trivy-isolated-scanner-v1-'+scope['operationId'], 'scope_root')
    before, after = instant(scope['notBefore']), instant(scope['expiresAt'])
    require(before <= now < after and 0 < (after-before).total_seconds() <= 3600, 'scope_expired')
    require(scope['limits'] == LIMITS and all(type(v) is int for v in scope['limits'].values()), 'scope_limits')
    for name in ('companyEvidence', 'feedEvidence'):
        closed(scope[name], ('sha256', 'bytes')); pin(scope[name], 65536)
    require(scope['companyEvidence'] == dict(sha256=digest(canonical(company)), bytes=len(canonical(company)))
            and scope['feedEvidence'] == dict(sha256=digest(canonical(feed)), bytes=len(canonical(feed))), 'independent_evidence_binding')
    closed(company, ('schemaVersion', 'status', 'image', 'version', 'entrypoint', 'imageInspectSHA256'))
    require(type(company['schemaVersion']) is int and company['schemaVersion'] == 1
            and company['status'] == 'company_approved_scanner'
            and type(company['image']) is str and IMAGE.fullmatch(company['image']) is not None
            and company['version'] == VERSION and company['entrypoint'] == '/usr/local/bin/trivy'
            and type(company['imageInspectSHA256']) is str and HASH.fullmatch(company['imageInspectSHA256']) is not None, 'unsupported_or_unapproved_scanner')
    closed(feed, ('directory', 'db', 'metadata', 'timestamps'))
    require(type(feed['directory']) is str and FEED.fullmatch(feed['directory']) is not None, 'feed_path')
    pin(feed['db'], 2*1024**3); pin(feed['metadata'], 65536)
    closed(feed['timestamps'], ('Version', 'UpdatedAt', 'NextUpdate', 'DownloadedAt'))
    t = feed['timestamps']; updated, next_at, downloaded = (instant(t[k]) for k in ('UpdatedAt', 'NextUpdate', 'DownloadedAt'))
    require(type(t['Version']) is int and t['Version'] == 2 and updated <= downloaded <= now < next_at
            and (now-updated).total_seconds() <= 86400, 'feed_freshness')


def fixture(case):
    require(case in VERSIONS, 'fixture_case')
    version = VERSIONS[case]
    return {'etc/os-release': b'ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n',
            'etc/debian_version': b'12.0\n',
            'var/lib/dpkg/status': ('Package: libcurl4\nStatus: install ok installed\nArchitecture: amd64\n'
                f'Source: curl ({version})\nVersion: {version}\nDescription: Synthetic inventory only\n\n').encode()}


def debian_version(package, source=False):
    prefix = 'Src' if source else ''
    v, release, epoch = package.get(prefix+'Version'), package.get(prefix+'Release', ''), package.get(prefix+'Epoch', 0)
    require(type(v) is str and type(release) is str and type(epoch) is int and epoch == 0, 'package_version')
    return v + ('-'+release if release else '')


def report(raw, case):
    value = parse(raw); require(type(value) is dict, 'report_type')
    require(type(value.get('SchemaVersion')) is int and value['SchemaVersion'] == 2
            and value.get('ArtifactName') == '/inventory' and value.get('ArtifactType') == 'filesystem'
            and type(value.get('Trivy')) is dict and value['Trivy'].get('Version') == VERSION, 'report_identity')
    metadata = value.get('Metadata'); require(type(metadata) is dict, 'report_metadata')
    os_value = metadata.get('OS'); require(type(os_value) is dict and os_value.get('Family') == 'debian'
            and os_value.get('Name') in ('12', '12.0')
            and ('EOSL' not in os_value or os_value['EOSL'] is False), 'report_os')
    results = value.get('Results'); require(type(results) is list and len(results) == 1, 'report_results')
    row = results[0]; require(type(row) is dict and row.get('Class') == 'os-pkgs' and row.get('Type') == 'debian'
            and type(row.get('Target')) is str and '/inventory' in row['Target'], 'report_class')
    packages = row.get('Packages'); require(type(packages) is list and len(packages) == 1, 'package_inventory')
    package = packages[0]; require(type(package) is dict and package.get('Name') == 'libcurl4'
            and package.get('SrcName') == 'curl' and debian_version(package) == VERSIONS[case]
            and debian_version(package, True) == VERSIONS[case], 'expected_package')
    vulnerabilities = row.get('Vulnerabilities', []); require(type(vulnerabilities) is list and len(vulnerabilities) <= 512, 'vulnerability_list')
    expected = []
    for item in vulnerabilities:
        require(type(item) is dict and type(item.get('VulnerabilityID')) is str
                and type(item.get('PkgName')) is str and type(item.get('InstalledVersion')) is str
                and item.get('Severity') in ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'), 'vulnerability_record')
        if item['VulnerabilityID'] == CVE:
            require(item['PkgName'] == 'libcurl4' and item['InstalledVersion'] == VERSIONS[case]
                    and item.get('FixedVersion') == VERSIONS['fixed'] and type(item['Severity']) is str and item['Severity'] in ('MEDIUM', 'HIGH', 'CRITICAL')
                    and type(item.get('DataSource')) is dict and item['DataSource'].get('ID') == 'debian', 'expected_advisory')
            expected.append(item)
    require(len(expected) == (1 if case == 'vulnerable' else 0), 'advisory_boundary')
    return dict(case=case, packageVersion=VERSIONS[case], expectedAdvisoryPresent=bool(expected), otherFindings=len(vulnerabilities)-len(expected))


@dataclass(frozen=True)
class CommandResult:
    stdout: bytes = b''
    stderr: bytes = b''
    exit_code: int | None = 0
    reaped: bool = True
    group_absent: bool = True
    overflow: bool = False


def known(result):
    require(type(result) is CommandResult and type(result.stdout) is bytes and type(result.stderr) is bytes, 'daemon_result')
    require(result.reaped is True and result.group_absent is True and result.overflow is False
            and type(result.exit_code) is int and result.exit_code == 0, 'daemon_outcome_unknown')


def selected_manifest(image):
    value = image.get('Descriptor')
    require(type(value) is dict and set(value) in ({'digest', 'mediaType', 'size'},
            {'digest', 'mediaType', 'size', 'platform'}), 'image_descriptor')
    require(value['digest'] == image['Id'] and value['mediaType'] in
            ('application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json')
            and type(value['size']) is int and 1 <= value['size'] <= 4*1024**2, 'image_descriptor')
    platform = {'architecture': 'amd64', 'os': 'linux'}
    require('platform' not in value or type(value['platform']) is dict
            and canonical(value['platform']) == canonical(platform), 'image_descriptor_platform')
    # Docker adds the selected platform to its container descriptor. Only this
    # exact platform may be derived from the authenticated linux/amd64 inspection.
    return dict(value, platform=platform)


def environment_values(value):
    require(type(value) is list and len(value) <= 3, 'container_environment')
    result = {}
    for item in value:
        require(type(item) is str and len(item) <= 4096 and '\n' not in item
                and '\r' not in item and '\x00' not in item and '=' in item, 'container_environment')
        name, content = item.split('=', 1)
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', name) is not None
                and name not in result, 'container_environment')
        result[name] = content
    return result


def request(scope, company, feed, case, environment, image_id, descriptor):
    args = ['--version', '--config='] if case == 'version' else list(SCANNER_ARGS)
    path_case = 'vulnerable' if case == 'version' else case
    return dict(name='as-feed-proof-'+scope['operationId']+'-'+case, operationId=scope['operationId'],
                image=company['image'], imageId=image_id, imageDescriptor=descriptor, entrypoint=company['entrypoint'],
                arguments=args, environment=environment+['HOME=/tmp', 'TMPDIR=/tmp'],
                mounts=[dict(source=feed['directory'], target='/cache/trivy/db', readonly=True),
                        dict(source=scope['root']+'/fixtures/'+path_case, target='/inventory', readonly=True)])


def create_argv(value):
    args = ['create', '--platform=linux/amd64', '--pull=never', '--name='+value['name'],
            '--hostname='+value['name'], '--label=io.autosoft.feed-qualification='+value['operationId'],
            '--runtime=runsc', '--network=none', '--ipc=private', '--restart=no', '--read-only',
            '--cap-drop=ALL', '--security-opt=no-new-privileges', '--user=10001:10001', '--workdir=/',
            '--cpus=2', '--memory='+str(LIMITS['memoryBytes']), '--memory-swap='+str(LIMITS['memoryBytes']),
            '--pids-limit=64', '--log-driver=none', '--no-healthcheck', '--stop-signal=SIGTERM',
            '--entrypoint='+value['entrypoint']]
    for path, options in TMPFS.items(): args.extend(('--tmpfs', path+':'+options))
    for item in value['mounts']:
        args.extend(('--mount', 'type=bind,src='+item['source']+',dst='+item['target']+',readonly,bind-propagation=rprivate'))
    for item in value['environment']: args.extend(('--env', item))
    return args+[value['image'], *value['arguments']]


def inspect_owned(raw, identifier, spec, baseline=None):
    rows = parse(raw); require(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict, 'container_inspection')
    m = rows[0]; c, h, state = m.get('Config'), m.get('HostConfig'), m.get('State')
    require(all(type(v) is dict for v in (c, h, state)), 'container_profile')
    require(m.get('Id') == identifier and m.get('Name') == '/'+spec['name'] and m.get('Image') == spec['image'].split('@')[1]
            and type(m.get('ImageManifestDescriptor')) is dict
            and canonical(m['ImageManifestDescriptor']) == canonical(spec['imageDescriptor'])
            and m['ImageManifestDescriptor'].get('digest') == spec['imageId']
            and m.get('Platform') == 'linux' and c.get('Image') == spec['image']
            and c.get('Cmd') == spec['arguments'] and c.get('Entrypoint') == [spec['entrypoint']]
            and c.get('User') == '10001:10001' and c.get('WorkingDir') == '/'
            and environment_values(c.get('Env')) == environment_values(spec['environment'])
            and c.get('Labels', {}).get('io.autosoft.feed-qualification') == spec['operationId']
            and c.get('Healthcheck') == {'Test': ['NONE']}, 'container_identity')
    exact = dict(Runtime='runsc', NetworkMode='none', IpcMode='private', PidMode='', UTSMode='', UsernsMode='',
                 ReadonlyRootfs=True, Privileged=False, AutoRemove=False, Memory=LIMITS['memoryBytes'],
                 MemorySwap=LIMITS['memoryBytes'], NanoCpus=LIMITS['nanoCpus'], PidsLimit=64,
                 CapDrop=['ALL'], Tmpfs=TMPFS, RestartPolicy={'Name': 'no', 'MaximumRetryCount': 0})
    for key, target in exact.items():
        require(type(h.get(key)) is type(target) and canonical(h[key]) == canonical(target), 'container_resources')
    require(h.get('SecurityOpt') in (['no-new-privileges'], ['no-new-privileges:true'])
            and h.get('LogConfig', {}).get('Type') == 'none'
            and (h.get('OomKillDisable') is None or h.get('OomKillDisable') is False) and 'OomKillDisable' in h, 'container_isolation')
    for key in ('CapAdd', 'PortBindings', 'Devices', 'DeviceRequests', 'DeviceCgroupRules', 'VolumesFrom',
                'ExtraHosts', 'Links', 'Sysctls', 'Binds', 'GroupAdd'):
        require(h.get(key) in (None, [], {}), 'container_extra_authority')
    mounts = m.get('Mounts'); require(type(mounts) is list and len(mounts) in (2, 4), 'container_mounts')
    binds = []; reported_tmpfs = []
    for item in mounts:
        require(type(item) is dict and type(item.get('Destination')) is str, 'container_mount')
        if item.get('Type') == 'bind':
            require(item.get('RW') is False and item.get('Propagation') == 'rprivate', 'readonly_mount')
            binds.append(dict(source=item.get('Source'), target=item.get('Destination'), readonly=True))
        else:
            require(item.get('Type') == 'tmpfs' and item.get('Destination') in TMPFS, 'container_tmpfs')
            reported_tmpfs.append(item['Destination'])
    require(len(binds) == 2 and sorted(binds, key=lambda x:x['target']) == sorted(spec['mounts'], key=lambda x:x['target'])
            and (not reported_tmpfs or len(reported_tmpfs) == 2 and set(reported_tmpfs) == set(TMPFS))
            and len({v['Destination'] for v in mounts}) == len(mounts), 'container_mount_binding')
    require(type(state.get('Running')) is bool and all(state.get(k) is False for k in ('OOMKilled', 'Dead', 'Paused', 'Restarting'))
            and state.get('Status') in ('created', 'running', 'exited'), 'container_state')
    profile_value = {k:m[k] for k in ('Id', 'Name', 'Image', 'Platform', 'Config', 'HostConfig', 'Mounts', 'ImageManifestDescriptor')}
    profile_value['Config'] = dict(c, Env=sorted(c['Env']))
    profile_value['HostConfig'] = dict(h, OomKillDisable=False)
    profile = digest(canonical(profile_value))
    require(baseline is None or profile == baseline, 'container_profile_drift')
    return state, profile


class Qualification:
    """Adapter interfaces: call(), journal.begin/put, guard.verify/close.

    Injected tests cannot qualify native behavior. Journal intent is never erased.
    """
    def __init__(self, daemon, journal, guard, *, clock=time.monotonic, utc=lambda:datetime.now(timezone.utc)):
        self.daemon, self.journal, self.guard = daemon, journal, guard
        self.clock, self.utc = clock, utc; self.used = False; self.calls = 0
        self.pending = True; self.owned = {}; self.start = None; self.unbound_create = False
        self.admission = None

    def call(self, argv, seconds=10, cleanup=False):
        self.calls += 1
        require(self.calls <= LIMITS['daemonCalls'], 'daemon_call_cap')
        deadline = self.start+LIMITS['wholeSeconds' if cleanup else 'activeSeconds']
        require(self.clock() < deadline, 'operation_deadline')
        if not cleanup and self.admission is not None: validate(*self.admission, self.utc())
        result = self.daemon.call(argv, min(seconds, deadline-self.clock()), LIMITS['stdoutBytes'], LIMITS['stderrBytes'])
        require(type(result) is CommandResult and type(result.stdout) is bytes and type(result.stderr) is bytes, 'daemon_result')
        require(len(result.stdout) <= LIMITS['stdoutBytes'] and len(result.stderr) <= LIMITS['stderrBytes'], 'daemon_output_cap')
        number = f'{self.calls:02d}'
        self.journal.command(canonical(dict(sequence=self.calls, argv=argv, stdoutSHA256=digest(result.stdout),
                         stdoutBytes=len(result.stdout), stderrSHA256=digest(result.stderr), stderrBytes=len(result.stderr),
                         exitCode=result.exit_code, reaped=result.reaped, groupAbsent=result.group_absent, overflow=result.overflow)))
        # Scan reports are the only larger retained outputs; other output is hash-bound.
        if argv[:2] == ['start', '--attach']:
            self.journal.put('stdout-'+number, result.stdout); self.journal.put('stderr-'+number, result.stderr)
        return result

    def inspect(self, identifier, spec, baseline=None, cleanup=False):
        value = self.call(['inspect', identifier], cleanup=cleanup); known(value)
        return inspect_owned(value.stdout, identifier, spec, baseline)

    def cleanup(self, identifier, spec, baseline):
        state, _ = self.inspect(identifier, spec, baseline, True)
        if state['Running']:
            known(self.call(['stop', '--time=15', identifier], 20, True))
        state, _ = self.inspect(identifier, spec, baseline, True)
        require(state['Running'] is False and state['Status'] in ('created', 'exited'), 'container_stop_unknown')
        known(self.call(['rm', identifier], 10, True))
        value = self.call(['ps', '--all', '--no-trunc', '--filter=id='+identifier, '--format={{.ID}}'], cleanup=True); known(value)
        require(value.stdout == b'', 'container_absence_unknown')
        self.journal.put('cleanup-'+identifier+'.json', canonical(dict(containerId=identifier, absenceConfirmed=True)))

    def run(self, scope, company, feed, *, allow_native=False):
        require(not self.used, 'one_shot_consumed'); self.used = True
        validate(scope, company, feed, self.utc())
        self.admission = (scope, company, feed)
        require(not self.daemon.native or allow_native is True and scope['nativeDispatch'] is True, 'native_dispatch_disabled')
        self.start = self.clock(); failure = None; cases = []; clean = True; preservation = False; released = False
        try:
            # Sibling creation changes the shared validation parent's metadata.
            # It therefore precedes the first original-feed ancestor snapshot.
            self.journal.begin(scope, {name:fixture(name) for name in VERSIONS})
            self.guard.verify(feed, self.start+LIMITS['activeSeconds'])
            validate(scope, company, feed, self.utc())
            observed = self.call(['image', 'inspect', '--platform=linux/amd64', company['image']]); known(observed)
            require(digest(observed.stdout) == company['imageInspectSHA256'], 'company_image_measurement')
            rows = parse(observed.stdout); require(type(rows) is list and len(rows) == 1, 'image_inventory')
            image = rows[0]; config = image.get('Config'); require(type(config) is dict and image.get('Os') == 'linux'
                and image.get('Architecture') == 'amd64' and type(image.get('Id')) is str
                and re.fullmatch('sha256:[a-f0-9]{64}', image['Id']) is not None
                and type(image.get('RepoDigests')) is list and company['image'] in image['RepoDigests']
                and all(type(v) is str for v in image['RepoDigests']) and config.get('Volumes') in (None, {}), 'image_identity')
            descriptor = selected_manifest(image)
            environment = config.get('Env') or []
            require(type(environment) is list and len(environment) <= 1
                    and all(type(v) is str and v.startswith('PATH=') and len(v) <= 4096 and '\n' not in v and '\x00' not in v for v in environment), 'image_environment')
            for case in ('version', 'vulnerable', 'fixed'):
                validate(scope, company, feed, self.utc()); self.guard.verify(feed, self.start+LIMITS['activeSeconds'], hash_content=False)
                spec = request(scope, company, feed, case, environment, image['Id'], descriptor)
                self.journal.put('create-intent-'+case+'.json', canonical(spec))
                self.unbound_create = True
                created = self.call(create_argv(spec)); identifier = created.stdout.decode('ascii', 'strict').removesuffix('\n')
                require(HASH.fullmatch(identifier) is not None, 'create_id_unknown')
                self.journal.put('created-'+case+'.json', canonical(dict(containerId=identifier)))
                state, baseline = self.inspect(identifier, spec)
                # Only this independently established immutable ID/profile is cleanup authority.
                self.owned[identifier] = (spec, baseline)
                self.unbound_create = False
                require(state['Status'] == 'created' and state['Running'] is False and state.get('Pid') == 0
                        and type(state.get('Pid')) is int and type(state.get('ExitCode')) is int and state['ExitCode'] == 0
                        and state.get('StartedAt') == state.get('FinishedAt') == '0001-01-01T00:00:00Z', 'never_started_unconfirmed')
                known(created)
                self.journal.put('start-intent-'+case+'.json', canonical(dict(containerId=identifier, profileSHA256=baseline)))
                self.inspect(identifier, spec, baseline)
                attached = self.call(['start', '--attach', identifier], 10 if case == 'version' else 120)
                known(attached); state, _ = self.inspect(identifier, spec, baseline)
                require(state['Status'] == 'exited' and state['Running'] is False and type(state.get('ExitCode')) is int and state['ExitCode'] == 0, 'scanner_exit')
                if case == 'version':
                    require(attached.stdout.startswith(('Version: '+VERSION+'\n').encode()), 'scanner_version')
                else:
                    cases.append(report(attached.stdout, case))
                self.cleanup(identifier, spec, baseline); del self.owned[identifier]
        except BaseException as error:
            failure = error.args[0] if type(error) is Unavailable else 'controller_unavailable'
        finally:
            for identifier, (spec, baseline) in list(self.owned.items()):
                try:
                    self.cleanup(identifier, spec, baseline); del self.owned[identifier]
                except BaseException: clean = False
            try:
                self.guard.verify(feed, self.start+LIMITS['wholeSeconds']); preservation = True
                if failure is None: validate(scope, company, feed, self.utc())
            except BaseException as error:
                if failure is None: failure = error.args[0] if type(error) is Unavailable else 'terminal_guard_unavailable'
            try:
                self.guard.close(); released = True
            except BaseException: pass
            try:
                self.daemon.close()
            except BaseException: released = False
            try:
                self.journal.close()
            except BaseException: released = False
        accepted = failure is None and clean and not self.owned and not self.unbound_create and preservation and released and len(cases) == 2
        if not accepted and failure is None: failure = 'preservation_or_release_unknown'
        result = dict(schemaVersion=1, status='isolated_os_probe_verified' if accepted else 'unavailable',
                      failureCode=failure, cleanupConfirmed=clean and not self.owned and not self.unbound_create,
                      originalFeedPreserved=preservation, ownedFilesReleased=released, cases=cases,
                      scopedReadOnlyLookupVerified=accepted, nativeObserved=type(self.daemon) is NativeDaemon,
                      companySecurityEligible=False, publisherSignatureVerified=False, fullDbIntegrityVerified=False, nativeImageScannerQualified=False,
                      javaCoverageQualified=False, globalDailyFeedQualified=False, backupReady=False,
                      controllerMemoryLimitEnforced=False, hostQuotaEnforced=False, productionQualified=False, automaticRetry=False,
                      remoteCancellationProven=False, promotionActions=0, serviceMutations=0)
        try:
            self.journal.put('result.json', canonical(result)); self.pending = not accepted
        except BaseException:
            result.update(status='unavailable', scopedReadOnlyLookupVerified=False, ownedFilesReleased=False, failureCode='result_retention_failed')
            self.pending = True
        return result


class NativeDaemon:
    """Local root CLI only. No socket, CLI config or credentials enter containers."""
    native = True
    def __init__(self, root):
        require(os.name == 'posix' and os.geteuid() == 0, 'native_root_only')
        require(not UNCERTAIN_NATIVE_OWNERS, 'native_release_unknown')
        self.config = str(Path(root)/'docker-config'); self.socket_fd = None
        self.socket = None; self.uncertain = False; self.processes = []
        try:
            self.socket_fd = os.open('/run/docker.sock', os.O_PATH|os.O_NOFOLLOW)
            socket = Path('/run/docker.sock').lstat()
            require(stat.S_ISSOCK(socket.st_mode) and socket.st_uid == 0 and socket.st_nlink == 1
                    and stat.S_IMODE(socket.st_mode) in (0o600, 0o660)
                    and Path('/var/run/docker.sock').resolve(strict=True) == Path('/run/docker.sock'), 'local_daemon_socket')
            require(metadata(os.fstat(self.socket_fd)) == metadata(socket), 'local_daemon_socket_binding')
            self.socket = metadata(socket)
        except BaseException:
            try: self.close()
            except BaseException: UNCERTAIN_NATIVE_OWNERS.append(self)
            raise

    def call(self, argv, timeout, out_cap, err_cap):
        require(not self.uncertain and not self.processes and not getattr(self, 'socket_close_unknown', False), 'daemon_cleanup_unknown')
        require(threading.active_count() == 1 and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL
                and hasattr(os, 'pidfd_open'), 'sole_reaper_required')
        require(type(argv) is list and argv and argv[0] in ('image', 'create', 'inspect', 'start', 'stop', 'rm', 'ps'), 'daemon_verb')
        require(type(timeout) in (int, float) and 5 < timeout <= 120, 'daemon_timeout_reserve')
        require(self.socket is not None and metadata(os.fstat(self.socket_fd)) == self.socket
                == metadata(Path('/run/docker.sock').lstat()), 'local_daemon_socket_drift')
        command = ['/usr/bin/docker', '--host=unix:///var/run/docker.sock', '--config='+self.config, *argv]
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True, shell=False, env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':self.config})
        self.processes.append(process)
        selector = None; pidfd = None; buffers = {}; code = None; overflow = False
        reaped = False; absent = False; releases = []; complete = False
        try:
            # Five seconds remain inside the supplied timeout for reap/close.
            pidfd = os.pidfd_open(process.pid, 0)
            selector = selectors.DefaultSelector(); deadline = time.monotonic()+timeout-5
            for pipe, cap in ((process.stdout, out_cap), (process.stderr, err_cap)):
                os.set_blocking(pipe.fileno(), False); selector.register(pipe, selectors.EVENT_READ, cap); buffers[pipe] = bytearray()
            while selector.get_map():
                require(time.monotonic() < deadline, 'daemon_timeout')
                for key, _ in selector.select(min(.1, max(0, deadline-time.monotonic()))):
                    try: raw = os.read(key.fileobj.fileno(), 65536)
                    except BlockingIOError: continue
                    if not raw: selector.unregister(key.fileobj); continue
                    allowed = key.data-len(buffers[key.fileobj]); buffers[key.fileobj].extend(raw[:max(0, allowed)])
                    if len(raw) > allowed: overflow = True; raise Unavailable('daemon_output_cap')
            while os.waitid(os.P_PID, process.pid, os.WEXITED|os.WNOHANG|os.WNOWAIT) is None:
                require(time.monotonic() < deadline, 'daemon_timeout'); time.sleep(.01)
            complete = True
        except BaseException: pass
        finally:
            # Sole reaper + successful WNOWAIT establishes the unreaped child.
            # None means a live child, not lost ownership. Never kill after reap.
            owned = False
            try:
                os.waitid(os.P_PID, process.pid, os.WEXITED|os.WNOHANG|os.WNOWAIT); owned = True
            except BaseException: releases.append('ownership')
            if owned:
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                except BaseException: releases.append('kill')
                try: code = process.wait(timeout=5); reaped = True
                except BaseException: releases.append('reap')
            if reaped:
                try: os.killpg(process.pid, 0)
                except ProcessLookupError: absent = True
                except BaseException: pass
            for item in (selector, process.stdout, process.stderr):
                if item is not None:
                    try: item.close()
                    except BaseException: releases.append('close')
            if pidfd is not None:
                try: os.close(pidfd); pidfd = None
                except BaseException: releases.append('pidfd_close')
            if reaped and absent and not releases:
                self.processes.remove(process)
            else:
                self.uncertain = True
                # Keep exact Popen/pipe/pidfd references for company reconciliation.
                self.processes[-1] = (process, selector, pidfd)
                if self not in UNCERTAIN_NATIVE_OWNERS: UNCERTAIN_NATIVE_OWNERS.append(self)
        return CommandResult(bytes(buffers.get(process.stdout, b'')), bytes(buffers.get(process.stderr, b'')),
                             code if complete else None, reaped and not releases, absent, overflow)

    def close(self):
        if self.socket_fd is not None:
            require(not getattr(self, 'socket_close_unknown', False), 'daemon_socket_release_unknown')
            try: os.close(self.socket_fd); self.socket_fd = None
            except BaseException:
                self.socket_close_unknown = True
                raise
        require(not self.uncertain and not self.processes, 'daemon_cleanup_unknown')


def metadata(info):
    return tuple(getattr(info, field) for field in FIELDS)


def encrypted_mount(raw, parent, device):
    require(type(raw) is bytes and len(raw) <= 65536, 'mountinfo_cap')
    covering = []
    try: lines = raw.decode('ascii', 'strict').splitlines()
    except UnicodeError: raise Unavailable('mountinfo_format') from None
    for line in lines:
        before, separator, after = line.partition(' - '); left = before.split(); right = after.split()
        require(bool(separator) and len(left) >= 6 and len(right) >= 3, 'mountinfo_format')
        target = left[4]
        if '\\' not in target and (parent == target or parent.startswith(target.rstrip('/')+'/')):
            covering.append((len(target), left[2], right[1]))
    require(bool(covering), 'encrypted_mount_missing')
    longest = max(v[0] for v in covering); selected = [v for v in covering if v[0] == longest]
    require(len(selected) == 1, 'encrypted_mount_ambiguous')
    _, numbers, source = selected[0]; pair = numbers.split(':')
    require(len(pair) == 2 and all(v.isdecimal() for v in pair)
            and tuple(map(int, pair)) == device and source == '/dev/mapper/autosoft-data', 'encrypted_mount_binding')
    return source


def metadata_timestamps(raw, expected):
    value = parse(raw, 65536)
    closed(value, ('Version', 'UpdatedAt', 'NextUpdate', 'DownloadedAt'))
    require(canonical(value) == canonical(expected), 'metadata_timestamps_binding')


class NativeFeedGuard:
    """Hold every canonical protected ancestor and file; stream, never open bbolt."""
    def __init__(self): self.directories = {}; self.files = {}; self.uncertain_closes = set()
    def verify(self, feed, deadline, *, hash_content=True):
        require(not self.uncertain_closes, 'feed_release_unknown')
        root = Path(feed['directory'])
        for path in reversed((root, *root.parents)):
            if path not in self.directories:
                fd = os.open(path, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                self.directories[path] = (fd, None)
                self.directories[path] = (fd, os.fstat(fd))
            fd, before = self.directories[path]; after = path.lstat()
            require(metadata(os.fstat(fd)) == metadata(before) == metadata(after)
                    and after.st_uid == 0 and not after.st_mode & 0o022, 'feed_ancestor')
        for leaf, name in (('trivy.db', 'db'), ('metadata.json', 'metadata')):
            path = root/leaf
            if path not in self.files:
                fd = os.open(leaf, os.O_RDONLY|os.O_NOFOLLOW, dir_fd=self.directories[root][0])
                self.files[path] = (fd, None)
                self.files[path] = (fd, os.fstat(fd))
            fd, before = self.files[path]; current = path.lstat()
            require(metadata(os.fstat(fd)) == metadata(before) == metadata(current)
                    and stat.S_ISREG(current.st_mode) and current.st_uid == 0 and current.st_nlink == 1
                    and stat.S_IMODE(current.st_mode) == 0o444 and current.st_size == feed[name]['bytes'], 'feed_file_binding')
            if not hash_content: continue
            os.lseek(fd, 0, os.SEEK_SET); h = hashlib.sha256(); count = 0; small = bytearray()
            while True:
                require(time.monotonic() < deadline, 'feed_hash_deadline'); raw = os.read(fd, 65536)
                if not raw: break
                count += len(raw); require(count <= feed[name]['bytes'], 'feed_hash_size'); h.update(raw)
                if name == 'metadata': small.extend(raw)
            require(count == feed[name]['bytes'] and h.hexdigest() == feed[name]['sha256']
                    and metadata(os.fstat(fd)) == metadata(before) == metadata(path.lstat()), 'feed_content_pin')
            if name == 'metadata': metadata_timestamps(bytes(small), feed['timestamps'])
    def close(self):
        failed = False
        for registry in (self.files, self.directories):
            for path, (fd, _) in list(registry.items()):
                if fd in self.uncertain_closes: failed = True; continue
                try: os.close(fd); del registry[path]
                except BaseException: failed = True; self.uncertain_closes.add(fd)
        require(not failed, 'feed_close_failed')


class NativeJournal:
    def __init__(self):
        self.root = None; self.bytes = 0; self.files = 0; self.command_fd = None
        self.directories = {}; self.owned_files = {}; self.closed_views = None; self.uncertain = False
        self.uncertain_closes = set()

    def hold_directory(self, path, mode=None):
        require(not self.uncertain, 'journal_release_unknown')
        fd = os.open(path, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        self.directories[path] = (fd, None)  # Ownership precedes fstat.
        if mode is not None: os.fchmod(fd, mode)  # Exclusively created directory only.
        info = os.fstat(fd); self.directories[path] = (fd, metadata(info))
        require(metadata(path.lstat()) == metadata(info) and stat.S_ISDIR(info.st_mode)
                and info.st_uid == 0 and not info.st_mode & 0o022, 'journal_directory')

    def verify_directories(self):
        require(not self.uncertain, 'journal_release_unknown')
        for path, (fd, before) in self.directories.items():
            require(before is not None and metadata(os.fstat(fd)) == before == metadata(path.lstat()), 'journal_directory_drift')

    def refresh(self, path):
        fd, before = self.directories[path]; info = os.fstat(fd)
        require(metadata(info) == metadata(path.lstat()) and metadata(info)[:5] == before[:5]
                and stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'journal_directory_drift')
        self.directories[path] = (fd, metadata(info))

    def fresh_directory(self, path, mode):
        self.verify_directories()
        os.mkdir(path.name, mode, dir_fd=self.directories[path.parent][0])
        self.refresh(path.parent); self.hold_directory(path, mode)
        os.fsync(self.directories[path.parent][0])

    def encrypted_parent(self, parent):
        fd = os.open('/proc/self/mountinfo', os.O_RDONLY|os.O_NOFOLLOW)
        self.owned_files[fd] = '/proc/self/mountinfo'
        try:
            raw = bytearray()
            while True:
                part = os.read(fd, min(65537-len(raw), 4096))
                if not part: break
                raw.extend(part); require(len(raw) <= 65536, 'mountinfo_cap')
            info = os.fstat(self.directories[parent][0])
            source = encrypted_mount(bytes(raw), str(parent), (os.major(info.st_dev), os.minor(info.st_dev)))
            mapper = Path(source).stat()
            require(stat.S_ISBLK(mapper.st_mode) and mapper.st_uid == 0 and mapper.st_rdev == info.st_dev, 'encrypted_mapper_binding')
        finally:
            self.release_file(fd)

    def release_file(self, fd):
        require(fd not in self.uncertain_closes, 'journal_release_unknown')
        try: os.close(fd); del self.owned_files[fd]
        except BaseException:
            self.uncertain = True; self.uncertain_closes.add(fd)
            raise

    def begin(self, scope, fixtures):
        self.root = Path(scope['root']); parent = self.root.parent
        require(parent.resolve(strict=True) == parent, 'journal_parent')
        for path in reversed((parent, *parent.parents)): self.hold_directory(path)
        self.encrypted_parent(parent)
        space = os.fstatvfs(self.directories[parent][0])
        require(space.f_bavail*space.f_frsize >= LIMITS['evidenceBytes']+64*1024**2, 'journal_available_space')
        self.fresh_directory(self.root, 0o700)  # No adoption, reset or deletion.
        self.put('dispatch-once.json', canonical(scope)); self.fresh_directory(self.root/'docker-config', 0o700)
        self.put('docker-config/config.json', b'{}\n'); self.fresh_directory(self.root/'fixtures', 0o755)
        for case, values in fixtures.items():
            directory = self.root/'fixtures'/case; self.fresh_directory(directory, 0o755)
            for relative, raw in values.items():
                target = directory/relative
                for path in reversed((target.parent, *target.parent.parents)):
                    if path.is_relative_to(directory) and path not in self.directories:
                        self.fresh_directory(path, 0o755)
                self.put('fixtures/'+case+'/'+relative, raw, 0o644)

    def command(self, raw):
        self.verify_directories()
        require(type(raw) is bytes and self.bytes+len(raw)+1 <= LIMITS['evidenceBytes'], 'journal_capacity')
        if self.command_fd is None:
            require(self.files < LIMITS['evidenceFiles'], 'journal_capacity')
            self.command_fd = os.open('commands.jsonl', os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_APPEND, 0o600,
                                      dir_fd=self.directories[self.root][0])
            self.owned_files[self.command_fd] = self.root/'commands.jsonl'; self.files += 1; self.refresh(self.root)
        info = os.fstat(self.command_fd)
        require(info.st_nlink == 1 and stat.S_ISREG(info.st_mode)
                and metadata(info) == metadata((self.root/'commands.jsonl').lstat()), 'command_journal_binding')
        row = raw+b'\n'; offset = 0; self.bytes += len(row)
        while offset < len(row):
            written = os.write(self.command_fd, row[offset:]); require(written > 0, 'journal_write')
            offset += written
        os.fsync(self.command_fd)
        os.fsync(self.directories[self.root][0]); self.verify_directories()

    def close(self):
        views = dict(self.directories)
        failed = self.uncertain
        try: self.verify_directories()
        except BaseException: failed = True
        for fd in list(self.owned_files):
            try: self.release_file(fd)
            except BaseException: failed = True
        self.command_fd = None if self.command_fd not in self.owned_files else self.command_fd
        for path, (fd, _) in reversed(list(self.directories.items())):
            if fd in self.uncertain_closes: failed = True; continue
            try: os.close(fd); del self.directories[path]
            except BaseException: failed = True; self.uncertain_closes.add(fd)
        self.uncertain = failed
        if not failed: self.closed_views = {path: view for path, (_, view) in views.items()}
        require(not failed, 'journal_release_unknown')

    def put(self, name, raw, mode=0o600):
        # Final result follows release of command resources. Reopen only the same
        # protected directory identities, then close every newly owned FD.
        terminal = not self.directories and self.closed_views is not None
        if terminal:
            require(name == 'result.json' and not self.uncertain, 'journal_final_only')
            try:
                for path, before in self.closed_views.items():
                    self.hold_directory(path)
                    require(self.directories[path][1] == before, 'journal_directory_drift')
                self.closed_views = None
                self.put(name, raw, mode)
            finally: self.close()
            return
        self.verify_directories()
        require(type(raw) is bytes and self.files < LIMITS['evidenceFiles'] and self.bytes+len(raw) <= LIMITS['evidenceBytes'], 'journal_capacity')
        require(type(name) is str and re.fullmatch('[A-Za-z0-9_./-]+', name) is not None, 'journal_path')
        path = self.root/name
        require(path.is_relative_to(self.root) and '..' not in Path(name).parts and path.parent in self.directories, 'journal_path')
        fd = os.open(path.name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, mode, dir_fd=self.directories[path.parent][0])
        self.owned_files[fd] = path
        self.files += 1; self.bytes += len(raw)
        try:
            os.fchmod(fd, mode); offset = 0
            while offset < len(raw):
                written = os.write(fd, raw[offset:]); require(written > 0, 'journal_write'); offset += written
            os.fsync(fd)
            info = os.fstat(fd)
            require(metadata(info) == metadata(path.lstat()) and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == mode and info.st_size == len(raw), 'journal_file_binding')
            self.refresh(path.parent); os.fsync(self.directories[path.parent][0]); self.verify_directories()
        finally: self.release_file(fd)


def protected_json(path, expected):
    pin(expected, 65536); path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, 'input_path')
    for ancestor in (path.parent, *path.parent.parents):
        info = ancestor.lstat(); require(info.st_uid == 0 and not info.st_mode & 0o022 and stat.S_ISDIR(info.st_mode), 'input_ancestor')
    before = path.lstat(); fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd); raw = os.read(fd, 65537)
        require(metadata(before) == metadata(opened) == metadata(os.fstat(fd)) == metadata(path.lstat())
                and stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and not before.st_mode & 0o022 and len(raw) == expected['bytes'] and digest(raw) == expected['sha256'], 'input_pin')
        value = parse(raw, 65536); require(canonical(value) == raw, 'canonical_input'); return value
    finally: os.close(fd)


def native_limits(resource):
    # RLIMIT_AS would also constrain the Go Docker CLI's virtual reservations.
    # Controller inputs/capture/JSON/writes are bounded; RSS is not OS-enforced.
    for kind, limit in ((resource.RLIMIT_CPU, 120), (resource.RLIMIT_NOFILE, 48),
                        (resource.RLIMIT_CORE, 0), (resource.RLIMIT_FSIZE, LIMITS['evidenceBytes'])):
        resource.setrlimit(kind, (limit, limit))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true'); parser.add_argument('--scope')
    parser.add_argument('--scope-sha256'); parser.add_argument('--scope-bytes', type=int)
    parser.add_argument('--company'); parser.add_argument('--feed')
    args = parser.parse_args(argv)
    if not args.native:
        print(canonical(dict(status='native_dispatch_disabled', scannerActions=0)).decode()); return 2
    guard = None; journal = None; daemon = None; armed = False
    try:
        require(os.name == 'posix' and os.geteuid() == 0, 'native_root_only')
        require(threading.active_count() == 1 and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, 'sole_reaper_required')
        def wall_deadline(*_): raise Unavailable('controller_wall_deadline')
        signal.signal(signal.SIGALRM, wall_deadline); signal.setitimer(signal.ITIMER_REAL, LIMITS['wholeSeconds'], 1); armed = True
        scope = protected_json(args.scope, dict(sha256=args.scope_sha256, bytes=args.scope_bytes))
        company = protected_json(args.company, scope['companyEvidence']); feed = protected_json(args.feed, scope['feedEvidence'])
        validate(scope, company, feed, datetime.now(timezone.utc)); require(scope['nativeDispatch'] is True, 'native_dispatch_disabled')
        import resource
        native_limits(resource)
        guard = NativeFeedGuard(); journal = NativeJournal(); daemon = NativeDaemon(scope['root'])
        result = Qualification(daemon, journal, guard).run(scope, company, feed, allow_native=True)
        print(canonical(result).decode()); return 0 if result['status'] == 'isolated_os_probe_verified' else 1
    except BaseException as error:
        code = error.args[0] if type(error) is Unavailable else 'native_controller_unavailable'
        print(canonical(dict(status='unavailable', failureCode=code, productionQualified=False)).decode()); return 1
    finally:
        if guard is not None:
            try: guard.close()
            except BaseException: pass
        for item in (daemon, journal):
            if item is not None:
                try: item.close()
                except BaseException:
                    if item not in UNCERTAIN_NATIVE_OWNERS: UNCERTAIN_NATIVE_OWNERS.append(item)
        if armed: signal.setitimer(signal.ITIMER_REAL, 0)


if __name__ == '__main__':
    raise SystemExit(main())

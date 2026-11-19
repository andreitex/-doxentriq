#!/usr/bin/env python3
"""Create a signed-bundle payload from concrete pushed company images."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from types import ModuleType

COMPANY_DEPLOYMENT = (
    'deploy/compose.yaml', 'deploy/config/grafana-datasources.yml',
    'deploy/config/loki.yml', 'deploy/config/mysql.cnf', 'deploy/config/otel.yml',
    'deploy/config/prometheus-web.yml', 'deploy/config/prometheus.yml',
    'deploy/config/rabbitmq.conf', 'deploy/config/redis.conf', 'deploy/config/squid.conf',
)


def _trusted_sibling(filename):
    """Company builder only: deterministic bytes, never ambient sibling imports."""
    if filename not in ('company_source.py', 'registry_manifest.py', 'platform_source.py') or os.name != 'posix':
        raise ValueError('Trusted company builder source unavailable')
    path = Path(__file__).with_name(filename)
    before = path.lstat()
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_mode & 0o022 or (before.st_uid, before.st_gid) != (os.getuid(), os.getgid()) or not 0 < before.st_size <= 1024**2:
        raise ValueError('Trusted company builder source unavailable')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        held = os.fstat(fd)
        raw = b''
        while len(raw) <= before.st_size:
            chunk = os.read(fd, min(65536, before.st_size + 1 - len(raw)))
            if not chunk: break
            raw += chunk
        after, current = os.fstat(fd), path.lstat()
        if len(raw) != before.st_size or any(getattr(before, field) != getattr(held, field) or getattr(held, field) != getattr(after, field) or getattr(after, field) != getattr(current, field) for field in fields):
            raise ValueError('Trusted company builder source unavailable')
    finally:
        os.close(fd)
    module = ModuleType('company_builder_' + filename.replace('.', '_'))
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def _exclusive(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_CLOEXEC', 0), 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def prepare_payload(directory, source_root, version, architecture, *, source_module=None,
                    source_files=None, owner_uid=0, owner_gid=0, created_at=None):
    """Fresh schema2 metadata only. Caller supplies an independently trusted tree."""
    directory = Path(directory)
    if type(version) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', version) is None or type(architecture) is not str or architecture != 'x86_64':
        raise ValueError('Supported company release version/architecture required')
    for name in ('company-sources.json', 'release.json'):
        if os.path.lexists(directory / name):
            raise ValueError('Company release metadata already exists; preserve partial state')
    source = source_module or _trusted_sibling('company_source.py')
    manifest = source.create(source_root, files=source_files, owner_uid=owner_uid, owner_gid=owner_gid)
    manifest_raw = source.encode(manifest)
    if len(manifest['files']) != 44 or 'scripts/verify-release.py' not in {row['path'] for row in manifest['files']}:
        raise ValueError('Exact company source catalog required')
    entries = {'company-sources.json': dict(bytes=len(manifest_raw), sha256=hashlib.sha256(manifest_raw).hexdigest())}
    # The reviewed source backend also measures the finite configuration set.
    # Its held FD/path/content rechecks apply; do not use mutable read_text paths.
    measured = source.create(directory, paths=('images.lock.json', 'runtime-manifest.json', 'approved-mirrors.json'),
                             files=source_files, owner_uid=owner_uid, owner_gid=owner_gid)
    for row in measured['files']:
        entries[row['path']] = dict(bytes=row['bytes'], sha256=row['sha256'])
    timestamp = created_at if created_at is not None else datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    if type(timestamp) is not str or re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', timestamp) is None:
        raise ValueError('Canonical UTC creation time required')
    datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%SZ')
    payload = dict(schemaVersion=2, version=version, createdAt=timestamp, architecture=architecture, files=entries)
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii') + b'\n'
    _exclusive(directory / 'company-sources.json', manifest_raw)
    _exclusive(directory / 'release.json', raw)
    return payload

def prepare_deployment_payload(directory, source_root, version, architecture, *, source_module=None,
                               source_files=None, owner_uid=0, owner_gid=0, created_at=None):
    """Trusted builder: schema3 source/config/template byte binding, no activation."""
    directory = Path(directory)
    if type(version) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', version) is None or type(architecture) is not str or architecture != 'x86_64':
        raise ValueError('Supported company release version/architecture required')
    for name in ('company-sources.json', 'company-deployment.json', 'release.json'):
        if os.path.lexists(directory / name):
            raise ValueError('Company release metadata already exists; preserve partial state')
    source = source_module or _trusted_sibling('company_source.py')
    if len(source.INSTALLER_RUNTIME_SOURCES) != 44 or 'scripts/verify-release.py' not in source.INSTALLER_RUNTIME_SOURCES:
        raise ValueError('Exact company source catalog required')
    # Measure all 54 inputs in one held snapshot; no directory discovery.
    measured = source.create(source_root, paths=(*source.INSTALLER_RUNTIME_SOURCES, *COMPANY_DEPLOYMENT),
                             files=source_files, owner_uid=owner_uid, owner_gid=owner_gid)
    sources = dict(schemaVersion=1, scope='COMPANY_SOURCE_BYTES_ONLY',
                   files=[row for row in measured['files'] if row['path'] in source.INSTALLER_RUNTIME_SOURCES])
    deployment = dict(schemaVersion=1, scope='COMPANY_DEPLOYMENT_BYTES_ONLY',
                      files=[row for row in measured['files'] if row['path'] in COMPANY_DEPLOYMENT])
    if tuple(row['path'] for row in deployment['files']) != COMPANY_DEPLOYMENT or sum(row['bytes'] for row in deployment['files']) > 4 * 1024**2:
        raise ValueError('Exact bounded company deployment catalog required')
    sources_raw = source.encode(sources)
    deployment_raw = json.dumps(deployment, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii') + b'\n'
    if len(deployment_raw) > 8192:
        raise ValueError('Bounded company deployment manifest required')
    entries = {name: dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
               for name, raw in (('company-sources.json', sources_raw), ('company-deployment.json', deployment_raw))}
    configs = source.create(directory, paths=('images.lock.json', 'runtime-manifest.json', 'approved-mirrors.json'),
                            files=source_files, owner_uid=owner_uid, owner_gid=owner_gid)
    for row in configs['files']:
        entries[row['path']] = dict(bytes=row['bytes'], sha256=row['sha256'])
    timestamp = created_at if created_at is not None else datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    if type(timestamp) is not str or re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', timestamp) is None:
        raise ValueError('Canonical UTC creation time required')
    datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%SZ')
    payload = dict(schemaVersion=3, version=version, createdAt=timestamp, architecture=architecture, files=entries)
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii') + b'\n'
    _exclusive(directory / 'company-sources.json', sources_raw)
    _exclusive(directory / 'company-deployment.json', deployment_raw)
    _exclusive(directory / 'release.json', raw)
    return payload


PLATFORM_HOST_SOURCES = ('scripts/autosoft.sh', 'scripts/backup_quiescence.py', 'scripts/backup_recovery.py', 'scripts/bootstrap.py', 'scripts/build-company-release.sh', 'scripts/certificates.sh', 'scripts/checkpoint_admission.py', 'scripts/company_source.py', 'scripts/host_kernel_security.py', 'scripts/host_package_inventory.py', 'scripts/identity.py', 'scripts/install-lock.sh', 'scripts/install-runtime-gate.sh', 'scripts/install.sh', 'scripts/installation_identity.py', 'scripts/installer_parent.py', 'scripts/keycloak-provision.mjs', 'scripts/keycloak-start.sh', 'scripts/lib.sh', 'scripts/maintenance-broker-security.mjs', 'scripts/maintenance.py', 'scripts/maintenance_broker_security.py', 'scripts/maintenance_image_export.py', 'scripts/maintenance_scanner.py', 'scripts/qualify-filesystem.py', 'scripts/qualify-samba.py', 'scripts/quota-helper.py', 'scripts/quota_allocation.py', 'scripts/quota_runtime.py', 'scripts/recovery_catalog.py', 'scripts/recovery_chain.py', 'scripts/recovery_services.py', 'scripts/recovery_tools.py', 'scripts/refresh-sources.py', 'scripts/registry_manifest.py', 'scripts/release-manifest.py', 'scripts/resolve-images.py', 'scripts/runtime_layout.py', 'scripts/runtime_pair_init.py', 'scripts/security-check.sh', 'scripts/sign-company-release.sh', 'scripts/startup_binding.py', 'scripts/storage-guard.sh', 'scripts/verify-release.py')

def prepare_platform_payload(directory,source_root,version,architecture,*,revision,git,
                             platform_module=None,source_module=None,platform_files=None,source_files=None,
                             owner_uid=0,owner_gid=0,created_at=None):
    """Explicit schema4 trusted producer; one complete clean Git capture, no sign."""
    directory = Path(directory)
    if type(version) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}',version) is None or architecture != 'x86_64':
        raise ValueError('Supported company release version/architecture required')
    if type(revision) is not str or re.fullmatch('[a-f0-9]{40}',revision) is None or git is None:
        raise ValueError('Explicit reviewed revision and bounded trusted Git adapter required')
    generated = ('company-sources.json','company-deployment.json','platform-sources.json','platform-sources.tar.gz','release.json')
    if any(os.path.lexists(directory/name) for name in generated):
        raise ValueError('Company release metadata already exists; preserve partial state')
    platform = platform_module or _trusted_sibling('platform_source.py')
    source = source_module or _trusted_sibling('company_source.py')
    if tuple(source.INSTALLER_RUNTIME_SOURCES) != PLATFORM_HOST_SOURCES:
        raise ValueError('Independent exact44 company source catalog required')
    timestamp = created_at if created_at is not None else datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    if type(timestamp) is not str or re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z',timestamp) is None:
        raise ValueError('Canonical UTC creation time required')
    datetime.strptime(timestamp,'%Y-%m-%dT%H:%M:%SZ')
    with platform.capture_git_revision(source_root,revision,git=git,backend=platform_files,uid=owner_uid,gid=owner_gid) as captured:
        captured.recheck(); rows = {}
        for name in (*PLATFORM_HOST_SOURCES,*COMPANY_DEPLOYMENT):
            raw = captured.files.get(name)
            if type(raw) is not bytes or not 0 < len(raw) <= 1024**2:
                raise ValueError('Complete capture does not contain exact host/template bytes')
            rows[name] = dict(path=name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        sources = dict(schemaVersion=1,scope='COMPANY_SOURCE_BYTES_ONLY',files=[rows[name] for name in PLATFORM_HOST_SOURCES])
        deployment = dict(schemaVersion=1,scope='COMPANY_DEPLOYMENT_BYTES_ONLY',files=[rows[name] for name in COMPANY_DEPLOYMENT])
        if sum(row['bytes'] for row in sources['files']) > 16*1024**2 or sum(row['bytes'] for row in deployment['files']) > 4*1024**2:
            raise ValueError('Bounded company host/template catalog required')
        encode = lambda value:json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')+b'\n'
        sources_raw,deployment_raw = encode(sources),encode(deployment)
        if len(sources_raw)>32768 or len(deployment_raw)>8192: raise ValueError('Bounded company catalogs required')
        platform.verify_archive(captured.manifest_bytes,captured.archive_bytes,host_manifest_raw=sources_raw,
            deployment_manifest_raw=deployment_raw,host_paths=PLATFORM_HOST_SOURCES,deployment_paths=COMPANY_DEPLOYMENT)
        measured = source.create(directory,paths=('images.lock.json','runtime-manifest.json','approved-mirrors.json'),
                                 files=source_files,owner_uid=owner_uid,owner_gid=owner_gid)
        entries = {row['path']:dict(bytes=row['bytes'],sha256=row['sha256']) for row in measured['files']}
        if set(entries) != {'images.lock.json','runtime-manifest.json','approved-mirrors.json'}:
            raise ValueError('Exact signed configuration set required')
        output = {'company-sources.json':sources_raw,'company-deployment.json':deployment_raw,
                  'platform-sources.json':captured.manifest_bytes,'platform-sources.tar.gz':captured.archive_bytes}
        entries.update({name:dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()) for name,raw in output.items()})
        payload = dict(schemaVersion=4,version=version,createdAt=timestamp,architecture=architecture,files=entries)
        output['release.json'] = encode(payload)
        # All capacity, capture, archive and exact catalog checks precede writes.
        captured.recheck()
        for name,raw in output.items():
            captured.recheck();_exclusive(directory/name,raw);captured.recheck()
        return payload


def digest(reference):
    evidence=_trusted_sibling('registry_manifest.py').qualify(reference)
    if 'evidence' not in digest.__dict__:digest.evidence=[]
    digest.evidence.append(evidence)
    return evidence['reference']


def bounded_git(argv, *, env, limit, timeout):
    """Trusted producer's bounded Git transport; no shell or ambient Git config.

    NativeGit supplies the fixed read-only query grammar. Both pipes share one
    finite memory budget; timeout/overflow kills and reaps the owned process
    group. Raw diagnostics stay out of release metadata and terminal output.
    """
    import selectors
    import signal
    import time
    if (os.name != 'posix' or type(limit) is not int or not 0 < limit <= 16 * 1024 ** 2
            or type(timeout) is not int or not 0 < timeout <= 30
            or type(argv) is not tuple or not argv or argv[0] != '/usr/bin/git'):
        raise ValueError('Bounded native company Git query required')
    process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
        start_new_session=True, cwd='/', bufsize=0)
    output, errors = bytearray(), bytearray()
    deadline = time.monotonic() + timeout
    reaped = False
    try:
        with selectors.DefaultSelector() as poll:
            for pipe, target in ((process.stdout, output), (process.stderr, errors)):
                os.set_blocking(pipe.fileno(), False)
                poll.register(pipe, selectors.EVENT_READ, target)
            while poll.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError('Company Git query exceeded its deadline')
                for key, unused in poll.select(min(remaining, .2)):
                    raw = os.read(key.fd, min(65536, limit + 1 - len(output) - len(errors)))
                    if not raw:
                        poll.unregister(key.fileobj)
                    else:
                        key.data.extend(raw)
                        if len(output) + len(errors) > limit:
                            raise ValueError('Company Git query exceeded its output limit')
            code = process.wait(timeout=max(.001, deadline - time.monotonic()))
            reaped = True
            if code != 0 or errors:
                raise ValueError('Company Git query failed; no source artifact emitted')
            return bytes(output)
    finally:
        # Fixed queries use no child helpers. Also remove descendants on an
        # abnormal exit so a failed producer cannot leave an inherited writer.
        if not reaped:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        process.stdout.close(); process.stderr.close()


def protected_producer_directories(directory, source_root):
    """Shared native producer boundary, not permission to trust candidate input."""
    if os.name != 'posix' or os.getuid() != os.getgid() or os.getuid() != 0:
        raise ValueError('Trusted root-owned Linux company producer required')
    for path in (directory, source_root):
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise ValueError('Exact absolute protected company directories required')
        for parent in (path, *path.parents):
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != info.st_gid or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('Protected company directory ancestry required')


class ProducerPrerequisiteUnavailable(ValueError):
    """An actionable fixed diagnostic before repository reads or output writes."""


def producer_git_prerequisite():
    """Check the actual fixed tool; never retry a repository read unprotected."""
    instruction = ('Use a company-approved, security-maintained Git package for this OS '
        'or an approved Linux builder. Do not remove --no-lazy-fetch or substitute '
        'an environment-only fallback.')
    if os.name != 'posix':
        raise ProducerPrerequisiteUnavailable('Company source production requires Linux. ' + instruction)
    environment = dict(PATH='/usr/bin:/bin', HOME='/nonexistent', LANG='C', LC_ALL='C', TZ='UTC',
        GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
        GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1')
    try:
        raw = bounded_git(('/usr/bin/git', '--version'), env=environment, limit=4096, timeout=10)
    except (OSError, ValueError):
        raise ProducerPrerequisiteUnavailable('Required /usr/bin/git is missing or cannot be checked. ' + instruction) from None
    parsed = re.fullmatch(rb'git version ([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,4})(?:[ .-][A-Za-z0-9._+-]{1,64})?\n', raw)
    if parsed is None:
        raise ProducerPrerequisiteUnavailable('Cannot identify the required /usr/bin/git version. ' + instruction)
    version = tuple(int(value) for value in parsed.groups())
    display = '.'.join(str(value) for value in version)
    if version < (2, 45, 1):
        raise ProducerPrerequisiteUnavailable('Company source capture requires Git 2.45.1 or newer; '
            'this host reports Git ' + display + '. ' + instruction)
    try:
        protected = bounded_git(('/usr/bin/git', '--no-lazy-fetch', '--version'),
            env=environment, limit=4096, timeout=10)
    except (OSError, ValueError):
        raise ProducerPrerequisiteUnavailable('Required /usr/bin/git cannot enforce --no-lazy-fetch. ' + instruction) from None
    if protected != raw:
        raise ProducerPrerequisiteUnavailable('Git prerequisite results disagree; keep the existing source unchanged. ' + instruction)
    return dict(scope='GIT_FUNCTIONAL_PREREQUISITE_ONLY', gitVersion=display,
        noLazyFetchOption=True, securityQualification=False, sourceCaptured=False)


def prepare_deployment_cli(argv):
    """Expose the original schema3 capture for a matching fresh foundation."""
    import argparse
    parser = argparse.ArgumentParser(description='Capture reviewed deployment source into a fresh schema3 release. Does not build/scan images, sign, install or activate.')
    parser.add_argument('directory', type=Path)
    parser.add_argument('source_root', type=Path)
    parser.add_argument('version')
    args = parser.parse_args(argv)
    protected_producer_directories(args.directory, args.source_root)
    result = prepare_deployment_payload(args.directory, args.source_root, args.version,
        'x86_64', owner_uid=0, owner_gid=0)
    raw = (args.directory / 'release.json').read_bytes()
    print(json.dumps(dict(scope='UNSIGNED_DEPLOYMENT_SOURCE_ONLY',
        schemaVersion=result['schemaVersion'], releaseSha256=hashlib.sha256(raw).hexdigest(),
        signed=False, imageSecurityQualified=False, installationActivated=False), sort_keys=True))


def prepare_platform_cli(argv):
    """Expose the existing schema4 producer without inventing image qualification."""
    import argparse
    parser = argparse.ArgumentParser(description='Capture reviewed clean Git source into a fresh schema4 release. Does not build/scan images, sign, install or activate.')
    parser.add_argument('directory', type=Path)
    parser.add_argument('source_root', type=Path)
    parser.add_argument('revision')
    parser.add_argument('version')
    args = parser.parse_args(argv)
    protected_producer_directories(args.directory, args.source_root)
    producer_git_prerequisite()
    # The three configuration files must already come from the reviewed image
    # pipeline. Their existence/hash is never labelled an image scan result.
    platform = _trusted_sibling('platform_source.py')
    result = prepare_platform_payload(args.directory, args.source_root, args.version,
        'x86_64', revision=args.revision, git=platform.NativeGit('/usr/bin/git', bounded_git),
        platform_module=platform, owner_uid=0, owner_gid=0)
    raw = (args.directory / 'release.json').read_bytes()
    print(json.dumps(dict(scope='UNSIGNED_COMPLETE_PLATFORM_SOURCE_ONLY',
        schemaVersion=result['schemaVersion'], sourceRevision=args.revision,
        releaseSha256=hashlib.sha256(raw).hexdigest(), signed=False,
        imageSecurityQualified=False, installationActivated=False), sort_keys=True))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == '--producer-preflight':
        if len(sys.argv) != 2: raise SystemExit('Usage: release-manifest.py --producer-preflight')
        try: print(json.dumps(producer_git_prerequisite(), sort_keys=True))
        except ProducerPrerequisiteUnavailable as error: raise SystemExit(str(error)) from None
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == '--complete-deployment-source':
        prepare_deployment_cli(sys.argv[2:])
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == '--complete-platform-source':
        try: prepare_platform_cli(sys.argv[2:])
        except ProducerPrerequisiteUnavailable as error: raise SystemExit(str(error)) from None
        sys.exit(0)
    directory, registry, version = Path(sys.argv[1]), sys.argv[2].rstrip("/"), sys.argv[3]
    complete_revision = os.environ.get('COMPLETE_PLATFORM_REVISION')
    if complete_revision:
        try: producer_git_prerequisite()
        except ProducerPrerequisiteUnavailable as error: raise SystemExit(str(error)) from None
    if any(os.path.lexists(directory / name) for name in ('company-sources.json', 'company-deployment.json', 'release.json')):
        raise SystemExit('Existing company release metadata must be preserved')
    images = json.loads((directory / "upstream.lock.json").read_text())
    images.update(platform=digest(f"{registry}/platform:{version}"), runtime=digest(f"{registry}/runtime:{version}"), dependency_proxy=digest(f"{registry}/proxy:{version}"))
    base = digest(f"{registry}/base-node:{version}")
    private = "registry:5000/base/node@" + base.split("@", 1)[1]
    manifest = dict(schemaVersion=1, registry="registry:5000", scannerImage=images["trivy"], scannerCache="/data/security-cache", dependencyProxy="http://dependency-proxy:3128", allowedPackageHosts=["registry.npmjs.org","pypi.org","files.pythonhosted.org"], templates={})
    manifest['serviceImages']={service:images[key] for service,key in {'mysql':'mysql','redis':'redis','rabbitmq':'rabbitmq','keycloak':'keycloak','registry':'registry','dependency-proxy':'dependency_proxy','control':'platform','worker':'platform','broker':'runtime','packager':'runtime','caddy':'caddy','prometheus':'prometheus','loki':'loki','grafana':'grafana','otel':'otel'}.items()}
    for name in ("node-web", "node-api", "node-worker", "node-mcp"):
        manifest["templates"][name] = dict(toolchainImage=base, runtimeImage=private, entrypoint=["node", "/app/server.mjs"], port=8080)
    mirrors = [dict(sourceImage=base, targetImage=private)]
    python_base=digest(f'{registry}/base-python:{version}')
    python_private='registry:5000/base/python@'+python_base.split('@',1)[1]
    manifest['templates']['python-api']=dict(toolchainImage=python_base,runtimeImage=python_private,entrypoint=['python','/app/server.py'],port=8080)
    mirrors.append(dict(sourceImage=python_base,targetImage=python_private))
    qualification=directory/'reports/samba-protocol.json'
    if qualification.exists():
        report=json.loads(qualification.read_text())
        if report.get('status')!='passed' or report.get('encryptedDialect')!='SMB3.1.1' or report.get('fixtureOnly') is not True:
            raise SystemExit('Only successful actual synthetic SMB protocol qualification can enable the connector')
        connector_source=digest(f'{registry}/samba-connector:{version}')
        current_id=subprocess.check_output(['docker','image','inspect','--format','{{.Id}}',f'{registry}/samba-connector:{version}'],text=True).strip()
        current_source=(Path(__file__).resolve().parents[1]/'deploy/connectors/samba.py').read_bytes()
        if report.get('connectorImageID')!=current_id or report.get('sourceSha256')!=hashlib.sha256(current_source).hexdigest():
            raise SystemExit('Connector qualification no longer matches the exact built image/source')
        connector_private='registry:5000/connectors/samba@'+connector_source.split('@',1)[1]
        images['samba_connector']=connector_source
        manifest['connectors']={'samba':dict(image=connector_private,protocolQualification=dict(status='passed',reportSha256=hashlib.sha256(qualification.read_bytes()).hexdigest(),checkedAt=report['checkedAt'],scope='synthetic-samba-server'))}
        mirrors.append(dict(sourceImage=connector_source,targetImage=connector_private))
    recovery_scan=directory/'reports/mysql-recovery.json'
    if recovery_scan.exists():
        # The fixed recovery Dockerfile checks signed exact MySQL client RPMs;
        # company pipeline scan gates run before this prepared manifest.
        images['mysql_recovery']=digest(f'{registry}/mysql-recovery:{version}')
    filesystem_qualification=directory/'reports/filesystem-protocol.json'
    if filesystem_qualification.exists():
        report=json.loads(filesystem_qualification.read_text())
        filesystem_source=digest(f'{registry}/filesystem-connector:{version}')
        current_id=subprocess.check_output(['docker','image','inspect','--format','{{.Id}}',f'{registry}/filesystem-connector:{version}'],text=True).strip()
        current_source=(Path(__file__).resolve().parents[1]/'deploy/connectors/filesystem.py').read_bytes()
        source_hash=hashlib.sha256(current_source).hexdigest()
        if report.get('status')!='passed' or report.get('fixtureOnly') is not True or report.get('scope')!='synthetic-readonly-filesystem-runsc' or report.get('connectorImageID')!=current_id or report.get('sourceSha256')!=source_hash:
            raise SystemExit('Filesystem qualification must match the exact real runsc-tested image and company source')
        filesystem_private='registry:5000/connectors/filesystem@'+filesystem_source.split('@',1)[1]
        images['filesystem_connector']=filesystem_source
        manifest.setdefault('connectors',{})['filesystem']=dict(image=filesystem_private,sourceSha256=source_hash,protocolQualification=dict(status='passed',reportSha256=hashlib.sha256(filesystem_qualification.read_bytes()).hexdigest(),checkedAt=report['checkedAt'],scope='synthetic-readonly-filesystem-runsc'))
        mirrors.append(dict(sourceImage=filesystem_source,targetImage=filesystem_private))
    for name, payload in (("images.lock.json", images), ("runtime-manifest.json", manifest), ("approved-mirrors.json", mirrors)):
        (directory / name).write_text(json.dumps(payload, indent=2) + "\n")
    if complete_revision:
        platform = _trusted_sibling('platform_source.py')
        prepare_platform_payload(directory, Path(__file__).resolve().parents[1], version,
            'x86_64', revision=complete_revision, git=platform.NativeGit('/usr/bin/git', bounded_git),
            platform_module=platform, owner_uid=os.getuid(), owner_gid=os.getgid())
    else:
        prepare_deployment_payload(directory, Path(__file__).resolve().parents[1], version,
                        subprocess.check_output(["uname", "-m"], text=True).strip(),
                        owner_uid=os.getuid(), owner_gid=os.getgid())
    reports=directory/'reports';reports.mkdir(exist_ok=True)
    (reports/'registry-content.json').write_text(json.dumps(dict(schemaVersion=1,scope='Target registry manifest/config/available layer comparison against independently inspected Linux amd64 source images',images=digest.evidence),indent=2)+'\n')

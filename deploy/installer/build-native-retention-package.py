"""Emit an independently delivered company retention worker, never sign/install.

Run on a trusted root-owned company checkout. The printed digest must travel
through the company's authenticated delivery channel; it cannot authenticate
itself. Candidate release bytes never select their verifier or native worker.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from types import ModuleType

PROGRAMS = {
    'cli': 'deploy/installer/company_full_cli.py',
    'delivery': 'deploy/installer/build-full-cli-package.py',
    'record': 'deploy/installer/company_cli_record.py',
    'store': 'deploy/installer/company_cli_executed_record_store.py',
    'crypto': 'deploy/installer/company_release_crypto.py',
    'station': 'deploy/installer/company_native_station.py',
    'request': 'deploy/installer/company_full_cli_request.py',
    'records': 'deploy/installer/company_retention_records.py',
    'configuration': 'deploy/installer/company_configuration.py',
    'configuration_worker': 'deploy/installer/company_configuration_worker.py',
    'repository_io': 'deploy/installer/company_repository_io.py',
    'repository_worker': 'deploy/installer/company_repository_worker.py',
    'runtime_pair_parent': 'deploy/installer/company_runtime_pair_parent.py',
    'runtime_pair_worker': 'deploy/installer/company_runtime_pair_worker.py',
    'stored_startup': 'deploy/installer/company_stored_startup.py',
    'startup_worker': 'deploy/installer/company_startup_worker.py',
    'render_io': 'deploy/installer/company_render_io.py',
    'render_commands': 'deploy/installer/company_render_commands.py',
    'render_verify': 'deploy/installer/company_render_verify.py',
    'render_worker': 'deploy/installer/company_render_worker.py',
    'host_tool_profiles': 'deploy/installer/company_host_tool_profiles.py',
    'host_packages': 'deploy/installer/company_host_packages.py',
    'host_package_runtime': 'deploy/installer/company_host_package_runtime.py',
    'engine_packages': 'deploy/installer/company_engine_packages.py',
    'engine_native': 'deploy/installer/company_engine_native.py',
    'engine_elf': 'deploy/installer/company_engine_elf.py',
    'foundation_worker': 'deploy/installer/company_install.py',
    'infrastructure_host': 'deploy/installer/company_infrastructure_host.py',
    'infrastructure_policy': 'deploy/installer/company_infrastructure_policy.py',
    'infrastructure_io': 'deploy/installer/company_infrastructure_io.py',
    'infrastructure_transport': 'deploy/installer/company_infrastructure_transport.py',
    'infrastructure_probe': 'deploy/installer/company_infrastructure_probe.py',
    'infrastructure_commands': 'deploy/installer/company_infrastructure_commands.py',
    'infrastructure_evidence': 'deploy/installer/company_infrastructure_evidence.py',
    'infrastructure_verify': 'deploy/installer/company_infrastructure_verify.py',
    'infrastructure_predecessor': 'deploy/installer/company_infrastructure_predecessor.py',
    'infrastructure_worker': 'deploy/installer/company_infrastructure_worker.py',
    'identity_io': 'deploy/installer/company_identity_io.py',
    'identity_commands': 'deploy/installer/company_identity_commands.py',
    'identity_evidence': 'deploy/installer/company_identity_evidence.py',
    'identity_split': 'deploy/installer/company_identity_split.py',
    'identity_worker': 'deploy/installer/company_identity_worker.py',
    'identity_predecessor': 'deploy/installer/company_identity_predecessor.py',
    'quota_units': 'deploy/installer/company_quota_units.py',
    'quota_service': 'deploy/installer/company_quota_service.py',
    'quota_worker': 'deploy/installer/company_quota_worker.py',

}
MAX_WORKER = 2*1024**2
FIELDS = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')


def pin(raw): return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
def encoded(raw): return dict(**pin(raw), base64=base64.b64encode(raw).decode('ascii'))


def protected_read(path, maximum=131072):
    """Producer bootstrap read before executing any helper from the checkout."""
    path = Path(path)
    if not path.is_absolute(): raise ValueError('absolute-producer-path-required')
    ancestors = {parent: parent.lstat() for parent in path.parents}
    before = path.lstat()
    for info in ancestors.values():
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022:
            raise ValueError('protected-company-source-ancestor-required')
    if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0 or before.st_mode & 0o022 or before.st_nlink != 1 or not 0 < before.st_size <= maximum:
        raise ValueError('protected-company-source-required')
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        expected = tuple(getattr(before, key) for key in FIELDS)
        if tuple(getattr(os.fstat(fd), key) for key in FIELDS) != expected:
            raise ValueError('company-source-changed')
        raw = bytearray()
        while len(raw) < before.st_size:
            part = os.pread(fd, min(65536, before.st_size-len(raw)), len(raw))
            if not part: raise ValueError('company-source-short-read')
            raw.extend(part)
        if os.pread(fd, 1, len(raw)) or tuple(getattr(os.fstat(fd), key) for key in FIELDS) != expected or tuple(getattr(path.lstat(), key) for key in FIELDS) != expected:
            raise ValueError('company-source-changed')
        for parent, info in ancestors.items():
            if any(getattr(parent.lstat(), key) != getattr(info, key) for key in FIELDS):
                raise ValueError('company-source-ancestor-changed')
        return bytes(raw)
    finally:
        os.close(fd)


def module(name, raw):
    value = ModuleType(name)
    value.__file__ = '<company producer ' + name + '>'
    if name in sys.modules: raise ValueError('duplicate-producer-module')
    sys.modules[name] = value
    exec(compile(raw, value.__file__, 'exec'), value.__dict__)
    return value


def read_company_host_catalog(source_root,path,expected_sha256,*,reader=protected_read,maximum=16384):
    path=Path(path);source_root=Path(source_root).resolve(strict=True)
    if not path.is_absolute() or path.resolve(strict=True)!=path or path.is_relative_to(source_root):
        raise ValueError('independent-company-profile-input-required')
    raw=reader(path,maximum)
    if hashlib.sha256(raw).hexdigest()!=expected_sha256:
        raise ValueError('company-host-tool-catalog-digest-mismatch')
    return raw


def assemble(root, fingerprint, *, reader, host_tool_catalog=None, host_package_catalog=None, engine_catalog=None):
    if engine_catalog is not None and (host_tool_catalog is not None or host_package_catalog is not None):
        raise ValueError('mixed-vendor-and-company-catalogs-refused')
    root = Path(root)
    read = lambda name: reader(root/name, 131072)
    PB = module('native_retention_package_builder', read('deploy/installer/build-full-package.py'))
    D = module('native_retention_delivery_builder', read(PROGRAMS['delivery']))
    # All captures come from the trusted producer checkout. The signed source
    # verifier must later match the operational catalog exactly on the client.
    captures = {name: read(name) for name in set(PB.PACKAGE_PATHS) | set(D.LAUNCH_PATHS) | set(PB.OPERATIONAL_PATHS) | set(PROGRAMS.values())}
    package_pins = {name: pin(captures[name]) for name in PB.PACKAGE_PATHS}
    launch_pins = {name: pin(captures[name]) for name in D.LAUNCH_PATHS}
    catalog = {name: dict(**pin(captures[name]), gitMode='100644') for name in PB.OPERATIONAL_PATHS}
    captured_reader = lambda path, maximum: captures[path.relative_to(root).as_posix()]
    full = PB.assemble(root, fingerprint, package_pins=package_pins,
        operational_catalog=catalog, reader=captured_reader)
    delivery = D.assemble(root, launch_pins=launch_pins, package_pins=package_pins,
        operational_catalog=catalog, fingerprint=fingerprint, full_package_raw=full,
        full_package_pin=pin(full), reader=captured_reader)
    bootstrap = ('scripts/verify-release.py', 'scripts/installer_parent.py')
    package = dict(programs={label: encoded(captures[path]) for label, path in PROGRAMS.items()},
        delivery=base64.b64encode(delivery).decode('ascii'), authentication=dict(
            delivery_pin=pin(delivery), launch_pins=launch_pins, package_pins=package_pins,
            operational_catalog=catalog, fingerprint=fingerprint, full_package_pin=pin(full),
            bootstrap_records={path: base64.b64encode(captures[path]).decode('ascii') for path in bootstrap},
            bootstrap_pins={path: package_pins[path] for path in bootstrap}))
    worker = read('deploy/installer/company_native_retention.py')
    marker = b'PACKAGE = None  # @NATIVE_RETENTION_PACKAGE@'
    if worker.count(marker) != 1: raise ValueError('native-worker-template-unavailable')
    worker = worker.replace(marker, b'PACKAGE = '+repr(package).encode('ascii'))
    marker=b'HOST_TOOL_CATALOG = None  # @COMPANY_HOST_TOOL_CATALOG@'
    if worker.count(marker)!=1:raise ValueError('host-tool-catalog-template-unavailable')
    captured=None
    if host_tool_catalog is not None:
        # Producer input is independent of candidate source. This validates its
        # shape only; protected input provenance is the trusted producer's duty.
        profiles=module('native_host_tool_profile_validator',captures[PROGRAMS['host_tool_profiles']])
        profiles.decode(host_tool_catalog,expected_catalog_sha256=hashlib.sha256(host_tool_catalog).hexdigest())
        captured=encoded(host_tool_catalog)
    worker=worker.replace(marker,b'HOST_TOOL_CATALOG = '+repr(captured).encode('ascii'))
    marker=b'HOST_PACKAGE_CATALOG = None  # @COMPANY_HOST_PACKAGE_CATALOG@'
    if worker.count(marker)!=1:raise ValueError('host-package-catalog-template-unavailable')
    captured=None
    if host_package_catalog is not None:
        if host_tool_catalog is None:raise ValueError('matching-company-tool-catalog-required')
        packages=module('native_host_package_validator',captures[PROGRAMS['host_packages']])
        catalog=packages.decode(host_package_catalog,hashlib.sha256(host_package_catalog).hexdigest(),profiles)
        for row in catalog['profiles']:
            tools=profiles.bind(host_tool_catalog,expected_catalog_sha256=hashlib.sha256(host_tool_catalog).hexdigest(),observed_platform=row['platform'])
            packages.bind(host_package_catalog,expected_catalog_sha256=hashlib.sha256(host_package_catalog).hexdigest(),observed_platform=row['platform'],host_tools=tools,profiles=profiles)
        captured=encoded(host_package_catalog)
    worker=worker.replace(marker,b'HOST_PACKAGE_CATALOG = '+repr(captured).encode('ascii'))
    marker=b'HOST_ENGINE_CATALOG = None  # @COMPANY_HOST_ENGINE_CATALOG@'
    if worker.count(marker)!=1:raise ValueError('engine-catalog-template-unavailable')
    captured=None
    if engine_catalog is not None:
        engine=module('native_company_engine_catalog_validator',captures[PROGRAMS['engine_packages']])
        engine.decode(engine_catalog,expected_catalog_sha256=hashlib.sha256(engine_catalog).hexdigest())
        captured=encoded(engine_catalog)
    worker=worker.replace(marker,b'HOST_ENGINE_CATALOG = '+repr(captured).encode('ascii'))
    if len(worker) > MAX_WORKER: raise ValueError('native-worker-package-limit')
    return worker


def assemble_entry(root, worker, *, reader, configuration=False, repository=False, runtime_pair=False, continuation=False, render=False, preparation=False, infrastructure=False, initialization=False, quota=False):
    root = Path(root)
    if any(type(v) is not bool for v in (configuration,repository,runtime_pair,continuation,render,preparation,infrastructure,initialization,quota)) or sum((configuration,repository,runtime_pair,continuation,render,preparation,infrastructure,initialization,quota))>1:
        raise ValueError('exact-companion-entry-scope-required')
    path = 'company-initialize.sh' if initialization or quota else 'company-infrastructure.sh' if infrastructure else 'company-prepare.sh' if preparation else 'company-render.sh' if render else 'company-continue.sh' if continuation else 'company-runtime-pair.sh' if runtime_pair else 'company-repository.sh' if repository else 'company-configure.sh' if configuration else 'company-retention.sh'
    entry = reader(root/('deploy/installer/'+path),32768)
    if quota:
        start=b'  final_outcome=$(_il_hash "private-initialization-only-v1:'
        end=b'}\ncompany_initialize_entry "$@"\n'
        entry=entry.replace(b'\r\n',b'\n')
        if entry.count(start)!=1 or not entry.endswith(end):raise ValueError('exact-initialization-tail-required')
        tail=reader(root/'deploy/installer/company-quota-stage.sh',8192)
        if b'\r' in tail or not tail.endswith(b'\n'):raise ValueError('quota-stage-lf-required')
        entry=entry[:entry.index(start)]+tail+end
        entry=entry.replace(b'--retain-render-and-initialize-private',b'--retain-render-initialize-and-start-quota')
    if continuation or render or infrastructure or initialization or quota:
        retention = reader(root/'deploy/installer/company-retention.sh',32768)
        start = b'  for stage in company-platform-store company-source-materialize; do\n'
        # The existing template is LF-normalized below solely for extraction.
        retention = retention.replace(b'\r\n',b'\n')
        if retention.count(start)!=1 or entry.count(b'# @EMBED_RETENTION_STAGE_LOOP@')!=1:
            raise ValueError('exact-retention-loop-required')
        begin=retention.index(start);end=retention.index(b'  done\n',begin)+len(b'  done\n')
        entry=entry.replace(b'# @EMBED_RETENTION_STAGE_LOOP@',retention[begin:end])
    lock = reader(root/'scripts/install-lock.sh',32768)
    if entry.count(b'# @EMBED_INSTALL_LOCK@') != 1 or entry.count(b'@WORKER_SHA256@') != 1:
        raise ValueError('retention-entry-template-unavailable')
    entry = entry.replace(b'# @EMBED_INSTALL_LOCK@',lock).replace(b'@WORKER_SHA256@',pin(worker)['sha256'].encode('ascii'))
    if len(entry) > 32768: raise ValueError('retention-entry-package-limit')
    return entry


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('root', type=Path)
    p.add_argument('destination', type=Path)
    p.add_argument('--fingerprint', required=True)
    p.add_argument('--host-tool-catalog',type=Path,help='Independent protected company OS/tool catalog; never read from client requests')
    p.add_argument('--host-tool-catalog-sha256',help='Expected catalog digest from approved company qualification evidence')
    p.add_argument('--host-package-catalog',type=Path,help='Independent protected company package catalog paired with the host-tool catalog')
    p.add_argument('--host-package-catalog-sha256',help='Independent approved package catalog digest')
    p.add_argument('--engine-catalog',type=Path,help='Independent protected company schema2 catalog; exclusive with vendor catalogs')
    p.add_argument('--engine-catalog-sha256',help='Independent approved company schema2 catalog digest')
    p.add_argument('--entry', type=Path, help='Optional companion company-retention.sh beside company-native-retention.py')
    p.add_argument('--configuration-entry', type=Path, help='Optional companion company-configure.sh; prepares a verified quiet foundation before retention')
    p.add_argument('--repository-entry', type=Path, help='Optional companion company-repository.sh; seeds a quiet configured foundation without activating services')
    p.add_argument('--runtime-pair-entry', type=Path, help='Optional companion company-runtime-pair.sh; initializes fresh runtime admission/quota controls only')
    p.add_argument('--continuation-entry', type=Path, help='Optional company-continue.sh; retains and inspects stored startup in one session, without activation')
    p.add_argument('--render-entry', type=Path, help='Company Store/Source/startup/render successor; no activation')
    p.add_argument('--preparation-entry', type=Path, help='Company configuration/repository/runtime preparation with explicit verification-only recovery; no activation')
    p.add_argument('--infrastructure-entry', type=Path, help='Signed retention/render/private infrastructure only')
    p.add_argument('--initialization-entry', type=Path, help='Signed retention/render/private infrastructure and independent identity policy verification; no public activation')
    p.add_argument('--quota-entry', type=Path, help='Initial private identity followed by quota support only; public services and timers remain disabled')
    a = p.parse_args(argv)
    if os.name != 'posix' or os.geteuid() != os.getegid() or os.geteuid() != 0:
        raise ValueError('company-linux-root-producer-required')
    if (a.engine_catalog is None)!=(a.engine_catalog_sha256 is None):raise ValueError('independent-engine-catalog-and-digest-required')
    if a.engine_catalog is not None and any(value is not None for value in (a.host_tool_catalog,a.host_tool_catalog_sha256,a.host_package_catalog,a.host_package_catalog_sha256)):
        raise ValueError('mixed-vendor-and-company-catalogs-refused')
    engine_catalog=read_company_host_catalog(a.root,a.engine_catalog,a.engine_catalog_sha256,maximum=65536) if a.engine_catalog is not None else None
    catalog=None
    if (a.host_tool_catalog is None)!=(a.host_tool_catalog_sha256 is None):
        raise ValueError('host-tool-catalog-and-independent-digest-required')
    if a.host_tool_catalog is not None:
        catalog=read_company_host_catalog(a.root,a.host_tool_catalog,a.host_tool_catalog_sha256)
    package_catalog=None
    if (a.host_package_catalog is None)!=(a.host_package_catalog_sha256 is None):
        raise ValueError('host-package-catalog-and-independent-digest-required')
    if a.host_package_catalog is not None:
        package_catalog=read_company_host_catalog(a.root,a.host_package_catalog,a.host_package_catalog_sha256,maximum=32768)
    if (a.configuration_entry or a.preparation_entry or a.infrastructure_entry or a.initialization_entry or a.quota_entry) and engine_catalog is None and (catalog is None or package_catalog is None):
        raise ValueError('both-company-host-catalogs-required-for-configuration')
    worker = assemble(a.root, a.fingerprint, reader=protected_read,host_tool_catalog=catalog,host_package_catalog=package_catalog,engine_catalog=engine_catalog)
    entry = assemble_entry(a.root, worker, reader=protected_read) if a.entry else None
    configuration_entry = assemble_entry(a.root, worker, reader=protected_read, configuration=True) if a.configuration_entry else None
    repository_entry = assemble_entry(a.root, worker, reader=protected_read, repository=True) if a.repository_entry else None
    runtime_pair_entry = assemble_entry(a.root, worker, reader=protected_read, runtime_pair=True) if a.runtime_pair_entry else None
    continuation_entry = assemble_entry(a.root, worker, reader=protected_read, continuation=True) if a.continuation_entry else None
    render_entry = assemble_entry(a.root, worker, reader=protected_read, render=True) if a.render_entry else None
    preparation_entry = assemble_entry(a.root, worker, reader=protected_read, preparation=True) if a.preparation_entry else None
    if a.preparation_entry and (a.preparation_entry.parent != a.destination.parent or a.preparation_entry.name != 'company-prepare.sh' or a.destination.name != 'company-native-retention.py' or os.path.lexists(a.preparation_entry)):
        raise ValueError('fresh-exact-preparation-entry-required')
    if a.render_entry and (a.render_entry.parent != a.destination.parent or a.render_entry.name != 'company-render.sh' or a.destination.name != 'company-native-retention.py' or os.path.lexists(a.render_entry)):
        raise ValueError('fresh-exact-render-entry-required')
    if a.entry and (a.entry.parent != a.destination.parent or a.entry.name != 'company-retention.sh' or a.destination.name != 'company-native-retention.py' or a.entry.exists() or a.entry.is_symlink()):
        raise ValueError('fresh-exact-companion-entry-required')
    if a.configuration_entry and (a.configuration_entry.parent != a.destination.parent or a.configuration_entry.name != 'company-configure.sh' or a.destination.name != 'company-native-retention.py' or os.path.lexists(a.configuration_entry)):
        raise ValueError('fresh-exact-configuration-entry-required')
    if a.repository_entry and (a.repository_entry.parent != a.destination.parent or a.repository_entry.name != 'company-repository.sh' or a.destination.name != 'company-native-retention.py' or os.path.lexists(a.repository_entry)):
        raise ValueError('fresh-exact-repository-entry-required')
    if a.runtime_pair_entry and (a.runtime_pair_entry.parent != a.destination.parent or a.runtime_pair_entry.name != 'company-runtime-pair.sh' or a.destination.name != 'company-native-retention.py' or os.path.lexists(a.runtime_pair_entry)):
        raise ValueError('fresh-exact-runtime-pair-entry-required')
    if a.continuation_entry and (a.continuation_entry.parent != a.destination.parent or a.continuation_entry.name != 'company-continue.sh' or a.destination.name != 'company-native-retention.py' or os.path.lexists(a.continuation_entry)):
        raise ValueError('fresh-exact-continuation-entry-required')
    infrastructure_entry = assemble_entry(a.root, worker, reader=protected_read, infrastructure=True) if a.infrastructure_entry else None
    initialization_entry = assemble_entry(a.root, worker, reader=protected_read, initialization=True) if a.initialization_entry else None
    quota_entry = assemble_entry(a.root, worker, reader=protected_read, quota=True) if a.quota_entry else None
    for item, name in ((a.infrastructure_entry, 'company-infrastructure.sh'), (a.initialization_entry, 'company-initialize.sh'), (a.quota_entry, 'company-private-quota.sh')):
        if item and (item.parent != a.destination.parent or item.name != name or a.destination.name != 'company-native-retention.py' or os.path.lexists(item)):
            raise ValueError('fresh-exact-private-successor-entry-required')
    destination = a.destination
    if not destination.is_absolute(): raise ValueError('absolute-output-required')
    for parent in destination.parents:
        current = parent.lstat()
        if not stat.S_ISDIR(current.st_mode) or current.st_uid != current.st_gid or current.st_uid != 0 or current.st_mode & 0o022:
            raise ValueError('protected-output-ancestor-required')
    fd = os.open(destination, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC, 0o400)
    try:
        offset = 0
        while offset < len(worker):
            count = os.write(fd, worker[offset:offset+65536])
            if count <= 0: raise ValueError('short-package-write')
            offset += count
        os.fsync(fd)
    finally:
        os.close(fd)
    parent_fd = os.open(destination.parent, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try: os.fsync(parent_fd)
    finally: os.close(parent_fd)
    if protected_read(destination, MAX_WORKER) != worker: raise ValueError('package-readback-mismatch')
    for entry_path, entry_raw in ((a.entry, entry), (a.configuration_entry, configuration_entry), (a.repository_entry, repository_entry), (a.runtime_pair_entry, runtime_pair_entry), (a.continuation_entry, continuation_entry), (a.render_entry, render_entry), (a.preparation_entry, preparation_entry), (a.infrastructure_entry, infrastructure_entry), (a.initialization_entry, initialization_entry), (a.quota_entry, quota_entry)):
        if entry_raw is None: continue
        fd = os.open(entry_path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o400)
        try:
            offset = 0
            while offset < len(entry_raw):
                count = os.write(fd,entry_raw[offset:offset+65536])
                if count <= 0: raise ValueError('short-entry-write')
                offset += count
            os.fsync(fd)
        finally: os.close(fd)
        parent_fd = os.open(entry_path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try: os.fsync(parent_fd)
        finally: os.close(parent_fd)
        if protected_read(entry_path,32768) != entry_raw: raise ValueError('entry-readback-mismatch')
    print(json.dumps(dict(scope='COMPANY_RETENTION_WORKER_ONLY', path=str(destination),
        **pin(worker), entry=dict(path=str(a.entry),**pin(entry)) if entry is not None else None,
        configurationEntry=dict(path=str(a.configuration_entry),**pin(configuration_entry)) if configuration_entry is not None else None,
        repositoryEntry=dict(path=str(a.repository_entry),**pin(repository_entry)) if repository_entry is not None else None,
        runtimePairEntry=dict(path=str(a.runtime_pair_entry),**pin(runtime_pair_entry)) if runtime_pair_entry is not None else None,
        continuationEntry=dict(path=str(a.continuation_entry),**pin(continuation_entry)) if continuation_entry is not None else None,
        renderEntry=dict(path=str(a.render_entry),**pin(render_entry)) if render_entry is not None else None,
        preparationEntry=dict(path=str(a.preparation_entry),**pin(preparation_entry)) if preparation_entry is not None else None,
        infrastructureEntry=dict(path=str(a.infrastructure_entry),**pin(infrastructure_entry)) if infrastructure_entry is not None else None,
        initializationEntry=dict(path=str(a.initialization_entry),**pin(initialization_entry)) if initialization_entry is not None else None,
        quotaEntry=dict(path=str(a.quota_entry),**pin(quota_entry)) if quota_entry is not None else None,
        fullInstallerAvailable=False), sort_keys=True))


if __name__ == '__main__':
    main()

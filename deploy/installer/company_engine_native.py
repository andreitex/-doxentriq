"""Finite company-v2 inputs/readback; never grants source or parent authority.

The original authenticated worker supplies the original native station and live
authority checks. Catalog eligibility/signature approval remains external.
Vendor-v1 modules and bindings are intentionally separate.
"""
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
import re
import stat
from types import MappingProxyType

SCOPE = 'COMPANY_ENGINE_EXECUTION_INPUTS_V2_ONLY'
TOOL_SCOPE = 'COMPANY_ENGINE_TOOL_BINDING_V2_ONLY'
LIBRARY = '/usr/lib64/doxentriq-runtime/libseccomp.so.2'
RUNPATH = '/usr/lib64/doxentriq-runtime'
INTERPRETER = '/lib64/ld-linux-x86-64.so.2'
RUNC_NEEDED = frozenset(('libseccomp.so.2', 'libc.so.6', 'libgcc_s.so.1', 'libm.so.6',
                        'libdl.so.2', 'libpthread.so.0', 'librt.so.1', 'libresolv.so.2',
                        'ld-linux-x86-64.so.2'))

SUPPORT = {
    'engine': ('/usr/lib/systemd/system/docker.service', '/usr/lib/systemd/system/docker.socket',
        '/usr/share/doxentriq-engine/selinux/docker-af-alg-deny.cil',
        '/usr/share/doxentriq-engine/selinux/docker-af-vsock-deny.cil',
        '/usr/share/doxentriq-engine/selinux/docker_client.cil'),
    'cli': (), 'containerd': ('/usr/lib/systemd/system/containerd.service', LIBRARY), 'compose': ()}


def require(value, reason='Authenticated company engine inputs are unavailable'):
    if not value: raise ValueError(reason)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def bind(raw, *, expected_catalog_sha256, observed_platform, catalog):
    source = catalog.bind(raw, expected_catalog_sha256=expected_catalog_sha256, observed_platform=observed_platform)
    # Decoder accepts Debian data, but no company DEB execution adapter is qualified.
    require(source['platform']['osId'] == 'rocky', 'Company DEB execution is not implemented or qualified')
    artifacts = tuple(source['packages']) + (source['packageSigningKey'],)
    arguments = tuple(value for item in artifacts for value in (item['path'], item['sha256']))
    return MappingProxyType(dict(scope=SCOPE, source=source, catalogSha256=source['catalogSha256'],
        profileSha256=source['profileSha256'], qualificationReportSha256=source['qualificationReportSha256'],
        platform=source['platform'], root=source['root'], artifacts=artifacts, shellArguments=arguments))


def tool_binding(binding, catalog):
    require(type(binding) is MappingProxyType and binding.get('scope') == SCOPE)
    source = binding['source']
    pins = catalog.transport_pins(source)
    return MappingProxyType(dict(scope=TOOL_SCOPE, catalogSha256=source['catalogSha256'],
        profileSha256=source['profileSha256'], platform=source['platform'],
        qualificationReportSha256=source['qualificationReportSha256'],
        sourceManifestSha256=source['sourceManifestSha256'], distributionMetadataSha256=source['distributionMetadataSha256'],
        tools=MappingProxyType({name: MappingProxyType(value) for name, value in pins.items()}),
        installedToolsVerified=False, qualificationEvidenceVerified=False, parentAuthorityEstablished=False))


def payload_paths(package, catalog):
    role = package['role']
    licenses = tuple('/usr/share/licenses/' + package['name'] + '/' + name for name in ('LICENSES.tar.gz', 'NOTICE', 'SOURCE.json'))
    return sorted(catalog.EXECUTABLES[role] + SUPPORT[role] + licenses)


def payload(raw, package, catalog):
    require(type(raw) is bytes and 0 < len(raw) <= 65536 and sha(raw) == package['payloadInventorySha256'], 'Company payload inventory digest differs')
    value = json.loads(raw, object_pairs_hook=catalog.unique, parse_constant=lambda _: require(False))
    require(canonical(value) == raw and type(value) is dict
        and set(value) == {'schemaVersion', 'scope', 'package', 'files', 'linkage'}
        and type(value['schemaVersion']) is int and value['schemaVersion'] == 2
        and value['scope'] == 'COMPANY_ENGINE_PACKAGE_PAYLOAD')
    require(value['package'] == {key: package[key] for key in ('role', 'name', 'version', 'architecture')})
    if package['role'] == 'containerd': linkage_contract(value['linkage'])
    else: require(value['linkage'] is None)
    rows = value['files']
    require(type(rows) is list and all(type(row) is dict for row in rows))
    require([row.get('path') for row in rows] == payload_paths(package, catalog), 'Exact company payload file set required')
    expected_binaries = {item['path']: item for item in package['executables']}
    for row in rows:
        require(set(row) == {'path', 'bytes', 'sha256', 'mode', 'uid', 'gid', 'type'} and row['type'] == 'file')
        require(type(row['uid']) is int and type(row['gid']) is int and row['uid'] == row['gid'] == 0)
        binary = row['path'] in expected_binaries
        require(type(row['bytes']) is int and (64 if binary else 1) <= row['bytes'] <= (256 if binary else 32)*1024**2
            and type(row['mode']) is int and row['mode'] == (0o755 if binary else 0o644))
        catalog.pin(row['sha256'])
        if binary:
            require(all(row[key] == expected_binaries[row['path']][key] for key in ('path', 'bytes', 'sha256', 'mode')))
    return catalog.freeze(value)


def linkage_contract(value):
    require(type(value) is dict and set(value) == {'schemaVersion', 'scope', 'runc', 'library'})
    require(type(value['schemaVersion']) is int and value['schemaVersion'] == 1 and
            value['scope'] == 'COMPANY_PRIVATE_SECCOMP_ELF_CONTRACT')
    r, l = value['runc'], value['library']
    require(type(r) is dict and set(r) == {'path', 'needed', 'interpreter', 'runpath'} and
            r['path'] == '/usr/bin/runc' and r['interpreter'] == INTERPRETER and r['runpath'] == RUNPATH)
    require(type(r['needed']) is list and all(type(x) is str for x in r['needed']) and
            r['needed'] == sorted(set(r['needed'])) and {'libseccomp.so.2', 'libc.so.6'} <= set(r['needed']) <= RUNC_NEEDED)
    require(type(l) is dict and set(l) == {'path', 'needed', 'soname'} and
            l['path'] == LIBRARY and l['needed'] == ['libc.so.6'] and l['soname'] == 'libseccomp.so.2')
    return value


def plain_linkage(value):
    if value is None:
        return None
    return dict(schemaVersion=value['schemaVersion'], scope=value['scope'],
        runc={**dict(value['runc']), 'needed': list(value['runc']['needed'])},
        library={**dict(value['library']), 'needed': list(value['library']['needed'])})


def held_digest(fd, info, check, expected, check_authority):
    require(info['st_size'] == expected['bytes'])
    digest, offset = hashlib.sha256(), 0
    while offset < expected['bytes']:
        check_authority(); check()
        raw = os.pread(fd, min(1024**2, expected['bytes'] - offset), offset)
        require(bool(raw)); digest.update(raw); offset += len(raw)
    require(not os.pread(fd, 1, offset) and digest.hexdigest() == expected['sha256'])
    check(); check_authority()


@contextmanager
def held_payloads(binding, station, *, catalog, check_authority):
    require(type(binding) is MappingProxyType and binding.get('scope') == SCOPE)
    manifests, checks = [], []
    with ExitStack() as stack:
        for package in binding['source']['packages']:
            check_authority()
            path = binding['root'] + '/' + package['name'] + '.payload.json'
            fd, info, check = stack.enter_context(station.held_file(path, 65536))
            require(stat.S_IMODE(info['st_mode']) == 0o400 and 0 < info['st_size'] <= 65536)
            raw = os.pread(fd, 65537, 0)
            require(len(raw) == info['st_size'] and not os.pread(fd, 1, len(raw)))
            check(); manifests.append(payload(raw, package, catalog)); checks.append(check)
        def recheck():
            check_authority()
            for check in checks: check()
        recheck(); yield tuple(manifests), recheck; recheck()
    check_authority()


@contextmanager
def held_archives(binding, station, *, catalog, check_authority):
    """Four full manifests and exactly four archives + one key stay held."""
    require(type(binding) is MappingProxyType and binding.get('scope') == SCOPE)
    require(len(binding['artifacts']) == 5 and len(binding['shellArguments']) == 10)
    checks = []
    with held_payloads(binding, station, catalog=catalog, check_authority=check_authority) as (manifests, payload_check), ExitStack() as stack:
        for item in binding['artifacts']:
            check_authority()
            require(item['path'] == binding['root'] + '/' + item['filename'])
            fd, info, check = stack.enter_context(station.held_file(item['path'], item['bytes']))
            require(stat.S_IMODE(info['st_mode']) == 0o400)
            held_digest(fd, info, check, item, check_authority)
            checks.append(check)
        def recheck():
            payload_check(); check_authority()
            for check in checks: check()
        recheck()
        yield dict(arguments=binding['shellArguments'], payloads=manifests, recheck=recheck)
        recheck()
    check_authority()


def append_phase_arguments(command, inputs, *, binding):
    """Only validated company constants enter the fixed signed phase body."""
    require(type(binding) is MappingProxyType and binding.get('scope') == SCOPE)
    require(type(command) is list and len(command) == 13 and command[:4] == ['/bin/bash', '--noprofile', '--norc', '-c']
        and command[5] == 'company-foundation' and command[4].endswith('\ncompany_packages_v2_phase "$@"\n'))
    arguments = inputs['arguments']
    require(type(arguments) is tuple and arguments == binding['shellArguments'] and len(arguments) == 10)
    root = binding['root']
    require(re.fullmatch(r'/opt/autosoft-company/host-packages/[a-f0-9]{64}/[a-f0-9]{64}', root))
    for index, item in enumerate(binding['artifacts']):
        require(arguments[index*2] == root + '/' + item['filename'] and arguments[index*2+1] == item['sha256'])
    fingerprint = binding['source']['packageSigningKey']['fingerprint']
    require(re.fullmatch('[A-F0-9]{40}', fingerprint))
    rows = [dict(row) for manifest in inputs['payloads'] for row in manifest['files']]
    require(len(rows) == 27 and len({row['path'] for row in rows}) == 27)
    raw = canonical(rows).decode('ascii').strip()
    # Producer-reviewed fixed paths and numeric/hex values contain no shell quote.
    require("'" not in raw and '\n' not in raw and len(raw) <= 16384)
    inventories = canonical([dict(schemaVersion=manifest['schemaVersion'],scope=manifest['scope'],linkage=plain_linkage(manifest['linkage']),package=dict(manifest['package']),files=[dict(row) for row in manifest['files']]) for manifest in inputs['payloads']]).decode('ascii').strip()
    require("'" not in inventories and '\n' not in inventories and len(inventories)<=16384)
    prefix = "DOXENTRIQ_ENGINE_KEY_FINGERPRINT='" + fingerprint + "'\nDOXENTRIQ_ENGINE_PAYLOAD='" + raw + "'\nDOXENTRIQ_ENGINE_MANIFESTS='" + inventories + "'\n"
    result = list(command); result[4] = prefix + result[4]
    require(len(result[4].encode()) <= 65536)
    return result + list(arguments)


def installed_payload(binding, manifests, station, *, check_authority, elf):
    measured = {}
    pair = {}
    expected = plain_linkage(next(manifest['linkage'] for manifest in manifests if manifest['package']['role'] == 'containerd'))
    with ExitStack() as stack:
        checks = []
        for manifest in manifests:
            for row in manifest['files']:
                check_authority()
                fd, info, check = stack.enter_context(station.held_file(row['path'], row['bytes'], executable=row['mode'] == 0o755))
                require(info['st_uid'] == row['uid'] and info['st_gid'] == row['gid'] and stat.S_IMODE(info['st_mode']) == row['mode'])
                held_digest(fd, info, check, row, check_authority)
                if row['path'] in ('/usr/bin/runc', LIBRARY):
                    raw = os.pread(fd, row['bytes'] + 1, 0)
                    require(len(raw) == row['bytes'] and sha(raw) == row['sha256'])
                    pair[row['path']] = raw
                measured[row['path']] = dict(row)
                checks.append(check)
        require(len(measured) == 27 and set(pair) == {'/usr/bin/runc', LIBRARY})
        elf.verify_pair(pair['/usr/bin/runc'], pair[LIBRARY], expected)
        for check in checks: check()
        check_authority()
    check_authority()
    return measured


def package_query(binding):
    require(binding['scope'] == SCOPE and binding['platform']['osId'] == 'rocky')
    return ['/usr/bin/rpm', '-q', '--queryformat', '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n',
        '--', *(item['name'] for item in binding['source']['packages'])]


def package_rows(raw, binding):
    require(type(raw) is bytes and 0 < len(raw) <= 32768 and raw.endswith(b'\n'))
    rows = []
    for line in raw.decode('ascii').splitlines():
        fields = line.split('\t'); require(len(fields) == 3)
        name, version, architecture = fields
        if version.startswith('0:'): version = version[2:]
        rows.append(dict(name=name, version=version, architecture=architecture))
    expected = [{key: item[key] for key in ('name', 'version', 'architecture')} for item in binding['source']['packages']]
    require(len(rows) == 4 and len({row['name'] for row in rows}) == 4
        and sorted(rows, key=lambda x: x['name']) == sorted(expected, key=lambda x: x['name']), 'Installed company package identities differ')
    return sorted(rows, key=lambda x: x['name'])


def host_policy(station, runner, check_authority):
    """Read current group, policy enablement and labels; never change them."""
    def call(argv):
        with station.held_file(argv[0], 128*1024**2, executable=True) as (_, _, check):
            check_authority(); check()
            raw = runner.run(argv, 30)
            require(type(raw) is bytes and len(raw) <= 1024**2)
            check(); check_authority(); return raw
    group = call(['/usr/bin/getent', 'group', 'docker']).decode('ascii').splitlines()
    require(len(group) == 1)
    fields = group[0].split(':')
    require(len(fields) == 4 and fields[0] == 'docker' and re.fullmatch('[0-9]+', fields[2])
        and int(fields[2]) > 0 and fields[3] == '', 'Docker group membership requires IT reconciliation')
    gid = int(fields[2])
    accounts = call(['/usr/bin/getent', 'passwd']).decode('utf-8').splitlines()
    require(0 < len(accounts) <= 4096)
    for row in accounts:
        values = row.split(':'); require(len(values) == 7 and values[3].isdigit())
        require(int(values[3]) != gid, 'An account has the Docker primary group')
    # Password fields are inspected only in memory; never returned or logged.
    shadow = call(['/usr/bin/getent', 'gshadow', 'docker']).decode('ascii').splitlines()
    require(len(shadow) == 1)
    values = shadow[0].split(':')
    require(len(values) == 4 and values[0] == 'docker' and values[1].startswith(('!', '*'))
        and values[2] == values[3] == '', 'Docker group password or administrator assignment is unsafe')
    mode = call(['/usr/sbin/getenforce']).decode('ascii').strip()
    require(mode in ('Enforcing', 'Permissive', 'Disabled'))
    policies = []
    if mode != 'Disabled':
        modules = [row.split() for row in call(['/usr/sbin/semodule', '-lfull']).decode('ascii').splitlines()]
        for name in ('docker-af-alg-deny', 'docker-af-vsock-deny'):
            matches = [row for row in modules if len(row) >= 2 and row[1] == name]
            require(matches == [['400', name, 'cil']], 'Company SELinux deny policy is absent, shadowed or disabled')
            policies.append(dict(name=name, priority=400, language='cil'))
        call(['/usr/sbin/matchpathcon', '-V', '/usr/bin/docker-proxy', '/usr/bin/dockerd', '/usr/libexec/docker/docker-init',
            '/usr/bin/docker', '/usr/bin/containerd', '/usr/bin/containerd-shim-runc-v2', '/usr/bin/runc',
            '/usr/libexec/docker/cli-plugins/docker-compose', LIBRARY])
    return dict(dockerGroupGid=gid, dockerGroupMembers=[], dockerGroupPasswordLocked=True,
        selinuxMode=mode, enabledDenyPolicies=policies, executableLabelsVerified=mode != 'Disabled')


def readback(binding, tools, *, catalog, station, runner, check_authority, platform_observer, elf):
    require(binding['scope'] == SCOPE and tools['scope'] == TOOL_SCOPE)
    require(tools['catalogSha256'] == binding['catalogSha256'] and tools['profileSha256'] == binding['profileSha256'])
    with held_payloads(binding, station, catalog=catalog, check_authority=check_authority) as (manifests, manifest_check):
        with platform_observer(station) as (observed, platform_check):
            require(observed == dict(binding['platform']) == dict(tools['platform']))
            command = package_query(binding)
            with station.held_file(command[0], 128*1024**2, executable=True) as (_, _, query_check):
                check_authority(); query_check(); platform_check()
                rows = package_rows(runner.run(command, 30), binding)
                query_check(); platform_check(); check_authority()
            files = installed_payload(binding, manifests, station, check_authority=check_authority, elf=elf)
            policy = host_policy(station, runner, check_authority)
            platform_check(); manifest_check(); check_authority()
    check_authority()
    binaries = {name: value for name, value in files.items() if value['mode'] == 0o755}
    require(len(binaries) == 8)
    projected = catalog.transport_pins(binding['source'])
    require(all(all(files[item['path']][key] == item[key] for key in ('path', 'bytes', 'sha256')) for item in projected.values()))
    return dict(schemaVersion=2, scope='CURRENT_COMPANY_ENGINE_PACKAGE_READBACK',
        packageCatalogSha256=binding['catalogSha256'], packageProfileSha256=binding['profileSha256'],
        qualificationReportSha256=binding['source']['qualificationReportSha256'],
        sourceManifestSha256=binding['source']['sourceManifestSha256'],
        distributionMetadataSha256=binding['source']['distributionMetadataSha256'],
        platform=dict(binding['platform']), installedPackages=rows, installedExecutablePins=binaries,
        installedPayloadPins=files, payloadInventoryPins={item['name']: item['payloadInventorySha256'] for item in binding['source']['packages']},
        transportPins=projected, hostPolicy=policy)


def verify_evidence(value, binding, tools, *, current):
    require(type(value) is dict and value == current, 'Company foundation readback differs from current observation')
    require(set(value) == {'schemaVersion', 'scope', 'packageCatalogSha256', 'packageProfileSha256',
        'qualificationReportSha256', 'sourceManifestSha256', 'distributionMetadataSha256', 'platform',
        'installedPackages', 'installedExecutablePins', 'installedPayloadPins', 'payloadInventoryPins', 'transportPins', 'hostPolicy'})
    require(type(value['schemaVersion']) is int and value['schemaVersion'] == 2
        and value['scope'] == 'CURRENT_COMPANY_ENGINE_PACKAGE_READBACK')
    require(value['packageCatalogSha256'] == binding['catalogSha256'] == tools['catalogSha256']
        and value['packageProfileSha256'] == binding['profileSha256'] == tools['profileSha256']
        and value['platform'] == dict(binding['platform']) == dict(tools['platform']))
    for key in ('qualificationReportSha256', 'sourceManifestSha256', 'distributionMetadataSha256'):
        require(value[key] == binding['source'][key])
    return value

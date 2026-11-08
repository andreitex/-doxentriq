"""Company engine schema2 data contract; no install, download or trust authority.

The expected digest comes from independently authenticated company delivery.
Native OS observation and qualification of source, binaries, signatures, tests,
SBOMs and licenses are separate responsibilities. A self-supplied digest or
passing this decoder cannot authorize a package or a host operation.
"""
import hashlib
import json
import re
from types import MappingProxyType

MAX_BYTES = 65536
PREFIX = '/opt/autosoft-company/host-packages/'
ROLES = ('engine', 'cli', 'containerd', 'compose')
NAMES = dict(zip(ROLES, ('doxentriq-engine', 'doxentriq-cli', 'doxentriq-containerd', 'doxentriq-compose')))
EXECUTABLES = {
    'engine': ('/usr/bin/docker-proxy', '/usr/bin/dockerd', '/usr/libexec/docker/docker-init'),
    'cli': ('/usr/bin/docker',),
    'containerd': ('/usr/bin/containerd', '/usr/bin/containerd-shim-runc-v2', '/usr/bin/runc'),
    'compose': ('/usr/libexec/docker/cli-plugins/docker-compose',),
}
EVIDENCE = {'sbomSha256', 'buildProvenanceSha256', 'testEvidenceSha256', 'licenseBundleSha256', 'payloadInventorySha256'}


def require(value, reason='Company engine catalog refused'):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(value):
    require(type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None and value != '0' * 64)
    return value


def unique(rows):
    value = {}
    for key, item in rows:
        require(key not in value, 'Duplicate catalog key')
        value[key] = item
    return value


def platform(value):
    require(type(value) is dict and set(value) == {'osId', 'versionId', 'architecture'})
    require(value['osId'] in ('debian', 'rocky') and value['architecture'] == 'x86_64')
    require(type(value['versionId']) is str and re.fullmatch(r'[0-9]{1,2}(?:\.[0-9]{1,2})?', value['versionId']))
    require(value['versionId'].split('.')[0] in (('12', '13') if value['osId'] == 'debian' else ('9', '10')))
    return value['osId'], value['versionId'], value['architecture']


def freeze(value):
    if type(value) is dict:
        return MappingProxyType({key: freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(freeze(item) for item in value)
    return value


def decode(raw, *, expected_catalog_sha256):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES)
    require(sha(raw) == pin(expected_catalog_sha256), 'Independent company catalog digest mismatch')
    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: require(False))
        require(canonical(value) == raw, 'Canonical catalog bytes required')
    except (UnicodeError, TypeError, RecursionError) as error:
        raise ValueError('Malformed company engine catalog') from error
    require(type(value) is dict and set(value) == {'schemaVersion', 'scope', 'profiles'})
    require(type(value['schemaVersion']) is int and value['schemaVersion'] == 2
        and value['scope'] == 'COMPANY_HOST_PACKAGE_CATALOG')
    require(type(value['profiles']) is list and 1 <= len(value['profiles']) <= 16)
    identities = []
    for profile in value['profiles']:
        require(type(profile) is dict and set(profile) == {'platform', 'origin', 'releaseId', 'packageSigningKey',
            'qualificationReportSha256', 'sourceManifestSha256', 'distributionMetadataSha256', 'packages'})
        identity = platform(profile['platform'])
        require(identity not in identities, 'Duplicate platform profile')
        identities.append(identity)
        require(profile['origin'] == 'doxentriq')
        require(type(profile['releaseId']) is str and re.fullmatch('doxentriq-engine-[a-z0-9][a-z0-9.-]{0,95}', profile['releaseId']))
        for key in ('qualificationReportSha256', 'sourceManifestSha256', 'distributionMetadataSha256'):
            pin(profile[key])
        key = profile['packageSigningKey']
        require(type(key) is dict and set(key) == {'filename', 'bytes', 'sha256', 'fingerprint'})
        require(key['filename'] == 'doxentriq-engine.asc' and type(key['bytes']) is int and 1024 <= key['bytes'] <= 65536)
        require(type(key['fingerprint']) is str and re.fullmatch('[A-F0-9]{40}', key['fingerprint']) and key['fingerprint'] != '0' * 40)
        pin(key['sha256'])
        packages = profile['packages']
        require(type(packages) is list and len(packages) == len(ROLES))
        require(all(type(item) is dict for item in packages) and [item.get('role') for item in packages] == list(ROLES))
        architecture, suffix = ('amd64', 'deb') if identity[0] == 'debian' else ('x86_64', 'rpm')
        total = 0
        for item in packages:
            require(set(item) == {'role', 'name', 'version', 'architecture', 'filename', 'bytes', 'sha256', 'executables'} | EVIDENCE)
            require(item['name'] == NAMES[item['role']] and item['filename'] == item['name'] + '.' + suffix
                and item['architecture'] == architecture)
            version = item['version']
            require(type(version) is str and re.fullmatch('[A-Za-z0-9.+:~_-]{1,128}', version)
                and re.search(r'[.+~_-]doxentriq[.+~_-]', version), 'Explicit company build version required')
            require(identity[0] != 'rocky' or not version.startswith('0:'), 'RPM zero epochs must be omitted')
            require(type(item['bytes']) is int and 16384 <= item['bytes'] <= 256 * 1024**2)
            total += item['bytes']
            for key in EVIDENCE | {'sha256'}:
                pin(item[key])
            executables = item['executables']
            require(type(executables) is list and len(executables) == len(EXECUTABLES[item['role']]))
            require(all(type(binary) is dict and set(binary) == {'path', 'bytes', 'sha256', 'mode'} for binary in executables))
            require([binary['path'] for binary in executables] == list(EXECUTABLES[item['role']]))
            for binary in executables:
                require(type(binary['bytes']) is int and 64 <= binary['bytes'] <= 256 * 1024**2
                    and type(binary['mode']) is int and binary['mode'] == 0o755)
                pin(binary['sha256'])
        require(total <= 1024**3)
    require(identities == sorted(identities), 'Canonical profile order required')
    return value


def bind(raw, *, expected_catalog_sha256, observed_platform):
    wanted = platform(observed_platform)
    catalog = decode(raw, expected_catalog_sha256=expected_catalog_sha256)
    selected = [item for item in catalog['profiles'] if platform(item['platform']) == wanted]
    require(len(selected) == 1, 'Exact native platform profile required')
    profile = selected[0]
    profile_digest = sha(canonical(profile))
    root = PREFIX + expected_catalog_sha256 + '/' + profile_digest
    packages = [dict(item, path=root + '/' + item['filename']) for item in profile['packages']]
    key = dict(profile['packageSigningKey'], path=root + '/doxentriq-engine.asc')
    return freeze(dict(scope='COMPANY_ENGINE_PACKAGE_BINDING_V2_ONLY', catalogSha256=expected_catalog_sha256,
        profileSha256=profile_digest, platform=profile['platform'], releaseId=profile['releaseId'],
        qualificationReportSha256=profile['qualificationReportSha256'], sourceManifestSha256=profile['sourceManifestSha256'],
        distributionMetadataSha256=profile['distributionMetadataSha256'], packages=packages, packageSigningKey=key,
        root=root, signaturesVerified=False, qualificationEvidenceVerified=False, packagesInstalled=False,
        parentAuthorityEstablished=False))


def transport_pins(binding):
    """Finite data projection, explicitly not the vendor-v1 authority/binding."""
    require(type(binding) is MappingProxyType and binding.get('scope') == 'COMPANY_ENGINE_PACKAGE_BINDING_V2_ONLY')
    packages = {item['role']: item for item in binding['packages']}
    return {tool: {key: packages[role]['executables'][0][key] for key in ('path', 'bytes', 'sha256')}
        for tool, role in (('docker', 'cli'), ('compose', 'compose'))}

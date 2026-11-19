"""Native host-package observation shared by authenticated foundation/consumer.

Catalog data and this module arrive in the company-authenticated worker, never
in the administrator request. OS/package-manager tools are trusted host code.
This issues no parent capability, installs nothing, and accepts no success JSON.
"""
from contextlib import ExitStack, contextmanager
import base64
import hashlib
import json
import os
import platform
import re
import stat
from types import MappingProxyType

EVIDENCE_SCOPE = 'CURRENT_COMPANY_HOST_PACKAGE_READBACK'


def require(value, reason='Authenticated host package readback is unavailable'):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def captured(item, maximum):
    require(type(item) is dict and set(item) == {'bytes', 'sha256', 'base64'})
    require(type(item['bytes']) is int and 0 < item['bytes'] <= maximum)
    require(type(item['sha256']) is str and re.fullmatch('[a-f0-9]{64}', item['sha256']))
    require(type(item['base64']) is str and len(item['base64']) <= (maximum + 2) // 3 * 4)
    raw = base64.b64decode(item['base64'], validate=True)
    require(len(raw) == item['bytes'] and sha(raw) == item['sha256'])
    return raw, item['sha256']


def platform_value(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 16384 and b'\0' not in raw)
    selected = {}
    for line in raw.decode('utf-8').splitlines():
        if not line or line.startswith('#'):
            continue
        require('=' in line)
        key, value = line.split('=', 1)
        require(re.fullmatch('[A-Z_][A-Z0-9_]*', key))
        if key not in ('ID', 'VERSION_ID'):
            continue
        require(key not in selected)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        require(re.fullmatch('[a-z0-9.]+', value))
        selected[key] = value
    require(set(selected) == {'ID', 'VERSION_ID'})
    return dict(osId=selected['ID'], versionId=selected['VERSION_ID'], architecture='x86_64')


@contextmanager
def held_platform(station):
    """Short immutable observation; close before intentional package writes."""
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64')
    with ExitStack() as stack:
        fd, info, check = stack.enter_context(station.held_file('/usr/lib/os-release', 16384))
        raw = os.pread(fd, 16385, 0)
        require(len(raw) == info['st_size'])
        etc = os.open('/etc', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        stack.callback(os.close, etc)
        before = station.metadata(os.fstat(etc))
        require(before['st_uid'] == before['st_gid'] == 0 and not before['st_mode'] & 0o022)
        leaf = os.stat('os-release', dir_fd=etc, follow_symlinks=False)
        identity = station.metadata(leaf)
        other, target = None, None
        if stat.S_ISLNK(leaf.st_mode):
            require(leaf.st_uid == leaf.st_gid == 0 and leaf.st_nlink == 1)
            target = os.readlink('os-release', dir_fd=etc)
            require(target in ('../usr/lib/os-release', '/usr/lib/os-release'))
        else:
            otherfd, otherinfo, other = stack.enter_context(station.held_file('/etc/os-release', 16384))
            require(os.pread(otherfd, 16385, 0) == raw and otherinfo['st_size'] == len(raw))
        def recheck():
            check()
            require(station.metadata(os.fstat(etc)) == before == station.metadata(os.stat('/etc', follow_symlinks=False)))
            require(station.metadata(os.stat('os-release', dir_fd=etc, follow_symlinks=False)) == identity)
            if target is not None:
                require(os.readlink('os-release', dir_fd=etc) == target)
            if other:
                other()
        recheck()
        yield platform_value(raw), recheck
        recheck()


def bindings(catalogs, *, profiles, packages, observed_platform, engine=None, engine_native=None, engine_elf=None):
    if type(catalogs) is dict and set(catalogs) == {'engine'}:
        require(engine is not None and engine_native is not None)
        raw, digest = captured(catalogs['engine'], engine.MAX_BYTES)
        package = engine_native.bind(raw, expected_catalog_sha256=digest, observed_platform=observed_platform, catalog=engine)
        return package, engine_native.tool_binding(package, engine)
    require(type(catalogs) is dict and set(catalogs) == {'tools', 'packages'}, 'Company host catalogs are required before foundation effects')
    toolraw, toolsha = captured(catalogs['tools'], profiles.MAX_BYTES)
    packraw, packsha = captured(catalogs['packages'], packages.MAX_CATALOG)
    tools = profiles.bind(toolraw, expected_catalog_sha256=toolsha, observed_platform=observed_platform)
    package = packages.bind(packraw, expected_catalog_sha256=packsha, observed_platform=observed_platform, host_tools=tools, profiles=profiles)
    return package, tools


def query_command(package):
    names = [x['name'] for x in package['artifacts'][:-1]]
    if package['platform']['osId'] == 'rocky':
        return ['/usr/bin/rpm', '-q', '--queryformat', '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n', '--', *names]
    return ['/usr/bin/dpkg-query', '-W', '-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n', '--', *names]


def package_rows(raw, binding):
    require(type(raw) is bytes and 0 < len(raw) <= 32768 and raw.endswith(b'\n'))
    rows = []
    for line in raw.decode('ascii').splitlines():
        fields = line.split('\t')
        if binding['platform']['osId'] == 'debian':
            require(len(fields) == 4 and fields.pop() == 'installed')
        require(len(fields) == 3)
        name, version, architecture = fields
        # RPM's explicit zero epoch is semantically absent. Nonzero epochs remain.
        if binding['platform']['osId'] == 'rocky' and version.startswith('0:'):
            version = version[2:]
        rows.append(dict(name=name, version=version, architecture=architecture))
    expected = [{key: item[key] for key in ('name', 'version', 'architecture')} for item in binding['artifacts'][:-1]]
    require(len(rows) == 5 and len({row['name'] for row in rows}) == 5)
    require(sorted(rows, key=lambda x: x['name']) == sorted(expected, key=lambda x: x['name']), 'Installed package identity differs from the authenticated catalog')
    return sorted(rows, key=lambda x: x['name'])


def readback(package, tools, *, station, runner, check_authority, engine=None, engine_native=None, engine_elf=None):
    """Fresh exact package queries + held native binary hashes; no target exec."""
    if package.get('scope') == 'COMPANY_ENGINE_EXECUTION_INPUTS_V2_ONLY':
        require(engine is not None and engine_native is not None)
        require(engine_elf is not None, 'Authenticated ELF verifier is unavailable')
        return engine_native.readback(package, tools, catalog=engine, station=station, runner=runner,
            check_authority=check_authority, platform_observer=held_platform, elf=engine_elf)
    require(type(package) is MappingProxyType and type(tools) is MappingProxyType)
    command = query_command(package)
    with ExitStack() as stack:
        observed, platform_check = stack.enter_context(held_platform(station))
        require(observed == dict(package['platform']) == dict(tools['platform']))
        _, _, query_check = stack.enter_context(station.held_file(command[0], 128 * 1024**2, executable=True))
        check_authority(); query_check(); platform_check()
        raw = runner.run(command, 30)
        rows = package_rows(raw, package)
        query_check(); platform_check(); check_authority()
        measured = {}
        for name, expected in tools['tools'].items():
            fd, info, check = stack.enter_context(station.held_file(expected['path'], expected['bytes'], executable=True))
            require(info['st_size'] == expected['bytes'])
            digest, offset = hashlib.sha256(), 0
            while offset < expected['bytes']:
                check_authority(); check()
                part = os.pread(fd, min(1024**2, expected['bytes'] - offset), offset)
                require(part); digest.update(part); offset += len(part)
            require(not os.pread(fd, 1, offset) and digest.hexdigest() == expected['sha256'])
            check()
            measured[name] = {key: expected[key] for key in ('path', 'bytes', 'sha256')}
        query_check(); platform_check(); check_authority()
    check_authority()
    return dict(schemaVersion=1, scope=EVIDENCE_SCOPE, packageCatalogSha256=package['catalogSha256'],
                packageProfileSha256=package['profileSha256'], toolCatalogSha256=tools['catalogSha256'],
                toolProfileSha256=tools['profileSha256'], qualificationReportSha256=tools['qualificationReportSha256'],
                platform=dict(package['platform']), installedPackages=rows, installedToolPins=measured)


def verify_evidence(value, package, tools, *, current, engine_native=None):
    if package.get('scope') == 'COMPANY_ENGINE_EXECUTION_INPUTS_V2_ONLY':
        require(engine_native is not None)
        return engine_native.verify_evidence(value, package, tools, current=current)
    require(type(value) is dict and value == current, 'Foundation host packages no longer match independent readback')
    require(set(value) == {'schemaVersion', 'scope', 'packageCatalogSha256', 'packageProfileSha256', 'toolCatalogSha256',
        'toolProfileSha256', 'qualificationReportSha256', 'platform', 'installedPackages', 'installedToolPins'})
    require(type(value['schemaVersion']) is int and value['schemaVersion'] == 1 and value['scope'] == EVIDENCE_SCOPE)
    for key, expected in (('packageCatalogSha256', package['catalogSha256']), ('packageProfileSha256', package['profileSha256']),
                          ('toolCatalogSha256', tools['catalogSha256']), ('toolProfileSha256', tools['profileSha256']),
                          ('qualificationReportSha256', tools['qualificationReportSha256'])):
        require(value[key] == expected)
    require(value['platform'] == dict(package['platform']) == dict(tools['platform']))
    return value

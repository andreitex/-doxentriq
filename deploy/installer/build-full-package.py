"""Inert full-composition package builder; no signing, emission or activation.

The publisher supplies independently authenticated pins/catalog and an explicit
trusted reader. Returned JSON does not authenticate its own initial execution.
The original foundation producer and FullEntry six-member API are unchanged.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

SCOPE = 'FULL_INSTALLATION_COMPOSITION_ONLY'
PACKAGE_PATHS = (
    'scripts/company_captured_loader.py', 'scripts/verify-release.py',
    'scripts/installer_parent.py', 'scripts/company_source_guard.py',
    'scripts/company_source_guard_backend.py', 'scripts/installer_materialize.py',
    'deploy/installer/company_full_entry.py',
    'deploy/installer/company_stored_startup.py',
    'deploy/installer/company_full_plan.py',
)
OPERATIONAL_PATHS = (
    'scripts/bootstrap.py', 'scripts/checkpoint_admission.py',
    'scripts/company_platform_store.py', 'scripts/company_source_tree.py',
    'scripts/identity.py',
    'scripts/installation_identity.py', 'scripts/installer_parent.py',
    'scripts/platform_source.py', 'scripts/quota_allocation.py',
    'scripts/quota_runtime.py', 'scripts/registry_manifest.py',
    'scripts/resolve-images.py', 'scripts/runtime_layout.py',
    'scripts/runtime_pair_init.py', 'scripts/startup_binding.py',
    'scripts/verify-release.py',
)
MAX_CAPTURE_BYTES = 131072
MAX_SOURCE_BYTES = 256 * 1024
MAX_PACKAGE_BYTES = 512 * 1024
MAX_CATALOG_BYTES = 16 * 1024
MAX_OPERATIONAL_MEMBER = 8 * 1024 * 1024
MAX_OPERATIONAL_BYTES = 16 * 1024 * 1024
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
UNRELEASED = []


class FullPackageUnavailable(ValueError):
    pass


def require(value):
    if value is not True:
        raise FullPackageUnavailable('company-full-package-unavailable')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def _hash(value):
    require(type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None)
    return value


def _rows(value, paths, *, logical=False):
    require(type(value) is dict and set(value) == set(paths))
    rows = {}
    for path in paths:
        row = value[path]
        keys = {'bytes', 'sha256', 'gitMode'} if logical else {'bytes', 'sha256'}
        maximum = MAX_OPERATIONAL_MEMBER if logical else MAX_CAPTURE_BYTES
        require(type(row) is dict and set(row) == keys
                and type(row['bytes']) is int and 0 < row['bytes'] <= maximum)
        _hash(row['sha256'])
        if logical:
            # This producer's fixed Python-only station policy is 100644.
            require(type(row['gitMode']) is str and row['gitMode'] == '100644')
        rows[path] = dict(row)
    require(sum(row['bytes'] for row in rows.values()) <=
            (MAX_OPERATIONAL_BYTES if logical else MAX_SOURCE_BYTES))
    if logical:
        require(len(canonical(rows)) <= MAX_CATALOG_BYTES)
    return rows


def _inputs(package_pins, operational_catalog, fingerprint):
    fingerprint = _hash(fingerprint)
    pins = _rows(package_pins, PACKAGE_PATHS)
    catalog = _rows(operational_catalog, OPERATIONAL_PATHS, logical=True)
    for path in set(PACKAGE_PATHS) & set(OPERATIONAL_PATHS):
        require(pins[path] == {key: catalog[path][key] for key in ('bytes', 'sha256')})
    return pins, catalog, fingerprint


def _raw(raw, row):
    require(type(raw) is bytes and len(raw) == row['bytes'] and sha(raw) == row['sha256'])
    return raw


def validate_package(raw, *, package_pins, operational_catalog, fingerprint):
    """Validate exact inert bytes against external publisher trust inputs."""
    pins, catalog, fingerprint = _inputs(package_pins, operational_catalog, fingerprint)
    require(type(raw) is bytes and 0 < len(raw) <= MAX_PACKAGE_BYTES)
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        raise FullPackageUnavailable('company-full-package-unavailable') from None
    require(type(value) is dict and set(value) ==
            {'schemaVersion', 'scope', 'keyFingerprint', 'operationalCatalog', 'records'})
    require(type(value['schemaVersion']) is int and value['schemaVersion'] == 1
            and type(value['scope']) is str and value['scope'] == SCOPE
            and type(value['keyFingerprint']) is str and value['keyFingerprint'] == fingerprint)
    require(_rows(value['operationalCatalog'], OPERATIONAL_PATHS, logical=True) == catalog)
    require(type(value['records']) is dict and set(value['records']) == set(PACKAGE_PATHS))
    total = 0
    for path in PACKAGE_PATHS:
        row = value['records'][path]
        require(type(row) is dict and set(row) == {'bytes', 'sha256', 'base64'}
                and type(row['bytes']) is int and row['bytes'] == pins[path]['bytes']
                and type(row['sha256']) is str and row['sha256'] == pins[path]['sha256'])
        encoded = row['base64']
        require(type(encoded) is str and encoded.isascii()
                and len(encoded) == 4 * ((row['bytes'] + 2) // 3))
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            raise FullPackageUnavailable('company-full-package-unavailable') from None
        require(base64.b64encode(decoded).decode('ascii') == encoded)
        total += len(_raw(decoded, pins[path]))
    require(total <= MAX_SOURCE_BYTES and canonical(value) == raw)
    return value


def assemble(root, fingerprint, *, package_pins, operational_catalog, reader):
    """Capture nine modules and fifteen operational files; never execute them.

    reader(path, maximum) is explicitly trusted by the publisher. Its byte
    captures must match independent inputs. No reader/native fallback is chosen.
    This pure API emits no files; a future protected emitter is a separate slice.
    """
    require(not UNRELEASED and callable(reader)
            and isinstance(root, (str, Path)))
    root = Path(root)
    require(root.is_absolute())
    pins, catalog, fingerprint = _inputs(package_pins, operational_catalog, fingerprint)
    captures = {path: _raw(reader(root / path, pins[path]['bytes']), pins[path])
                for path in PACKAGE_PATHS}
    # Re-read the two overlaps too: the operational snapshot must be exact.
    for path in OPERATIONAL_PATHS:
        raw = _raw(reader(root / path, catalog[path]['bytes']), catalog[path])
        if path in captures:
            require(raw == captures[path])
    records = {path: dict(**pins[path], base64=base64.b64encode(captures[path]).decode('ascii'))
               for path in PACKAGE_PATHS}
    raw = canonical(dict(schemaVersion=1, scope=SCOPE, keyFingerprint=fingerprint,
                         operationalCatalog=catalog, records=records))
    validate_package(raw, package_pins=pins, operational_catalog=catalog, fingerprint=fingerprint)
    require(not UNRELEASED)
    return raw


def _identity(info):
    return tuple(getattr(info, key) for key in FIELDS)


def protected_read(path, maximum):
    """Explicit Linux/root reader; held full-nine path/FD continuity, no writes.

    Trusted station OS/interpreter and independently supplied pins remain
    prerequisites. This is not an I/O deadline or native qualification claim.
    """
    require(not UNRELEASED and os.name == 'posix' and sys.platform.startswith('linux')
            and type(maximum) is int and 0 < maximum <= MAX_OPERATIONAL_MEMBER
            and all(hasattr(os, name) for name in ('O_NOFOLLOW', 'O_CLOEXEC', 'O_DIRECTORY'))
            and os.geteuid() == 0 and os.getegid() == 0)
    path = Path(path)
    require(path.is_absolute() and path == Path(os.path.normpath(path)))
    owned, proofs = [], []
    try:
        for parent in reversed(path.parents):
            before = parent.lstat()
            require(stat.S_ISDIR(before.st_mode) and before.st_uid == 0 and before.st_gid == 0
                    and not (stat.S_IMODE(before.st_mode) & 0o022))
            fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            owned.append(fd)
            require(_identity(before) == _identity(os.fstat(fd)) == _identity(parent.lstat()))
            proofs.append((parent, fd, _identity(before)))
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_gid == 0
                and stat.S_IMODE(before.st_mode) == 0o644 and before.st_nlink == 1
                and 0 < before.st_size <= maximum)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        owned.append(fd)
        require(_identity(before) == _identity(os.fstat(fd)) == _identity(path.lstat()))
        proofs.append((path, fd, _identity(before)))
        raw = bytearray()
        while len(raw) <= maximum:
            part = os.read(fd, min(65536, maximum + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        require(len(raw) == before.st_size)
        for name, held, identity in proofs:
            require(identity == _identity(os.fstat(held)) == _identity(name.lstat()))
        return bytes(raw)
    finally:
        errors = []
        for fd in reversed(owned):
            try:
                os.close(fd)
            except BaseException as error:
                errors.append((fd, error))
        if errors:
            UNRELEASED.append((tuple(owned), tuple(errors), tuple(proofs)))
            raise FullPackageUnavailable('company-full-package-release-unknown')


def main():
    # Pure composition is usable through the explicit trusted-reader API. No
    # command line accepts a trust origin or silently emits/activates a package.
    print('company-full-package: explicit publisher API required; CLI disabled', file=sys.stderr)
    return 2


if __name__ == '__main__':
    raise SystemExit(main())

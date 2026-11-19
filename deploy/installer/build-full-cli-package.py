"""Pure full-retention launch delivery; no signing, compile, IO default or CLI.

Company publisher/entry authenticates this executing validator independently.
Output self-pins never establish initial trust. The original nine-member full
package remains unchanged. Every reader is explicit trusted publisher code.
"""
import base64
import hashlib
import json
from pathlib import Path
import re

SCOPE = 'FULL_RETENTION_CLI_DELIVERY_ONLY'
LAUNCH_PATHS = (
    'deploy/installer/company_full_cli.py',
    'deploy/installer/company_full_cli_request.py',
    'scripts/install-lock.sh',
    'deploy/installer/build-full-package.py',
    'deploy/installer/company_full_package_loader.py',
    'deploy/installer/company_stage_scope.py',
    'deploy/installer/company_full_retention_worker.py',
    'deploy/installer/company_retention_effects.py',
    'deploy/installer/company_parent_system.py',
    'deploy/installer/company_seed_backend.py',
    'deploy/installer/company_seed_runner.py',
)
PACKAGE_PATHS = (
    'scripts/company_captured_loader.py', 'scripts/verify-release.py',
    'scripts/installer_parent.py', 'scripts/company_source_guard.py',
    'scripts/company_source_guard_backend.py', 'scripts/installer_materialize.py',
    'deploy/installer/company_full_entry.py', 'deploy/installer/company_stored_startup.py',
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
    'scripts/runtime_pair_init.py', 'scripts/startup_binding.py', 'scripts/verify-release.py',
)
MAX_CAPTURE = 131072
MAX_LAUNCH_BYTES = 256 * 1024
MAX_FULL_PACKAGE = 512 * 1024
MAX_FULL_DECODED = 256 * 1024
MAX_CATALOG = 16 * 1024
MAX_OPERATIONAL_MEMBER = 8 * 1024 * 1024
MAX_OPERATIONAL_BYTES = 16 * 1024 * 1024
MAX_DELIVERY = 1024 * 1024


class FullCliPackageUnavailable(ValueError):
    pass


def require(value):
    if value is not True:
        raise FullCliPackageUnavailable('company-full-cli-package-unavailable')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def _hash(value):
    require(type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None)


def _pin(value, maximum):
    require(type(value) is dict and set(value) == {'bytes', 'sha256'}
            and type(value['bytes']) is int and 0 < value['bytes'] <= maximum)
    _hash(value['sha256'])
    return dict(value)


def _rows(value, paths, maximum, total, *, logical=False):
    require(type(value) is dict and set(value) == set(paths))
    rows = {}
    for path in paths:
        row = value[path]
        if logical:
            require(type(row) is dict and set(row) == {'bytes', 'sha256', 'gitMode'}
                    and type(row['gitMode']) is str and row['gitMode'] == '100644')
            row = {key: row[key] for key in ('bytes', 'sha256')}
        rows[path] = _pin(row, maximum)
        if logical:
            rows[path]['gitMode'] = '100644'
    require(sum(row['bytes'] for row in rows.values()) <= total)
    return rows


def _inputs(launch_pins, package_pins, operational_catalog, fingerprint, full_package_pin):
    _hash(fingerprint)
    launch = _rows(launch_pins, LAUNCH_PATHS, MAX_CAPTURE, MAX_LAUNCH_BYTES)
    package = _rows(package_pins, PACKAGE_PATHS, MAX_CAPTURE, MAX_FULL_DECODED)
    catalog = _rows(operational_catalog, OPERATIONAL_PATHS, MAX_OPERATIONAL_MEMBER, MAX_OPERATIONAL_BYTES, logical=True)
    require(len(canonical(catalog)) <= MAX_CATALOG)
    for path in set(PACKAGE_PATHS) & set(OPERATIONAL_PATHS):
        require(package[path] == {key: catalog[path][key] for key in ('bytes', 'sha256')})
    return launch, package, catalog, _pin(full_package_pin, MAX_FULL_PACKAGE)


def _raw(raw, pin):
    require(type(raw) is bytes and len(raw) == pin['bytes'] and sha(raw) == pin['sha256'])
    return raw


def _decode(raw, maximum):
    require(type(raw) is bytes and 0 < len(raw) <= maximum)
    try:
        value = json.loads(raw)
        require(type(value) is dict and canonical(value) == raw)
    except (ValueError, UnicodeError, TypeError, RecursionError, OverflowError):
        raise FullCliPackageUnavailable('company-full-cli-package-unavailable') from None
    return value


def _record(value, pin):
    require(type(value) is dict and set(value) == {'bytes', 'sha256', 'base64'}
            and type(value['bytes']) is int and value['bytes'] == pin['bytes']
            and type(value['sha256']) is str and value['sha256'] == pin['sha256'])
    encoded = value['base64']
    require(type(encoded) is str and encoded.isascii() and len(encoded) == 4 * ((pin['bytes'] + 2) // 3))
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError):
        raise FullCliPackageUnavailable('company-full-cli-package-unavailable') from None
    require(base64.b64encode(raw).decode('ascii') == encoded)
    return _raw(raw, pin)


def _full(raw, package, catalog, fingerprint, pin):
    value = _decode(_raw(raw, pin), MAX_FULL_PACKAGE)
    require(set(value) == {'schemaVersion', 'scope', 'keyFingerprint', 'operationalCatalog', 'records'}
            and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
            and value['scope'] == 'FULL_INSTALLATION_COMPOSITION_ONLY'
            and type(value['keyFingerprint']) is str and value['keyFingerprint'] == fingerprint)
    actual = _rows(value['operationalCatalog'], OPERATIONAL_PATHS, MAX_OPERATIONAL_MEMBER, MAX_OPERATIONAL_BYTES, logical=True)
    require(actual == catalog and type(value['records']) is dict and set(value['records']) == set(PACKAGE_PATHS))
    captured = {path: _record(value['records'][path], package[path]) for path in PACKAGE_PATHS}
    require(sum(map(len, captured.values())) <= MAX_FULL_DECODED)
    return captured


def _encoded(raw, pin):
    return dict(**pin, base64=base64.b64encode(raw).decode('ascii'))


def _shape(launch, fingerprint, full_pin):
    return dict(schemaVersion=1, scope=SCOPE, keyFingerprint=fingerprint,
                fullPackage=dict(**full_pin, base64=''),
                launchRecords={path: dict(**pin, base64='') for path, pin in launch.items()})


def validate_delivery(raw, *, delivery_pin, launch_pins, package_pins,
                      operational_catalog, fingerprint, full_package_pin):
    """Match externally authenticated pins before returning any captured bytes.

    These equality checks do not authenticate their caller's initial pin origin.
    The consumer still uses original Q/F/V registries and stage-specific guards.
    """
    launch, package, catalog, full_pin = _inputs(launch_pins, package_pins, operational_catalog, fingerprint, full_package_pin)
    value = _decode(_raw(raw, _pin(delivery_pin, MAX_DELIVERY)), MAX_DELIVERY)
    require(set(value) == {'schemaVersion', 'scope', 'keyFingerprint', 'fullPackage', 'launchRecords'}
            and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
            and value['scope'] == SCOPE and type(value['keyFingerprint']) is str and value['keyFingerprint'] == fingerprint
            and type(value['launchRecords']) is dict and set(value['launchRecords']) == set(LAUNCH_PATHS))
    full_raw = _record(value['fullPackage'], full_pin)
    full_captures = _full(full_raw, package, catalog, fingerprint, full_pin)
    captures = {path: _record(value['launchRecords'][path], launch[path]) for path in LAUNCH_PATHS}
    require(sum(map(len, captures.values())) <= MAX_LAUNCH_BYTES)
    return dict(launchCaptures=captures, fullPackage=full_raw, fullCaptures=full_captures,
                operationalCatalog=catalog, keyFingerprint=fingerprint)


def assemble(root, *, launch_pins, package_pins, operational_catalog,
             fingerprint, full_package_raw, full_package_pin, reader):
    """Capture complete independent launch/package/source inputs, emit inert JSON.

    No writes, signing, code compile, adapter construction or reader default.
    Future real CLI code and final WorkerV3 must exist before a real delivery.
    """
    require(callable(reader) and isinstance(root, (str, Path)))
    root = Path(root)
    require(root.is_absolute())
    launch, package, catalog, full_pin = _inputs(launch_pins, package_pins, operational_catalog, fingerprint, full_package_pin)
    full_captures = _full(full_package_raw, package, catalog, fingerprint, full_pin)
    shape = _shape(launch, fingerprint, full_pin)
    serialized_size = len(canonical(shape)) + sum(4 * ((pin['bytes'] + 2) // 3) for pin in (*launch.values(), full_pin))
    require(serialized_size <= MAX_DELIVERY)
    captured = {path: _raw(reader(root / path, launch[path]['bytes']), launch[path]) for path in LAUNCH_PATHS}
    for path in PACKAGE_PATHS:
        require(_raw(reader(root / path, package[path]['bytes']), package[path]) == full_captures[path])
    for path in OPERATIONAL_PATHS:
        row = catalog[path]
        raw = _raw(reader(root / path, row['bytes']), row)
        if path in full_captures:
            require(raw == full_captures[path])
    shape['fullPackage'] = _encoded(full_package_raw, full_pin)
    shape['launchRecords'] = {path: _encoded(captured[path], launch[path]) for path in LAUNCH_PATHS}
    result = canonical(shape)
    require(len(result) == serialized_size and len(result) <= MAX_DELIVERY)
    # Publisher self-consistency only; the eventual company entry receives an
    # independently authenticated delivery digest, never this self-hash as origin.
    validate_delivery(result, delivery_pin=dict(bytes=len(result), sha256=sha(result)),
        launch_pins=launch, package_pins=package, operational_catalog=catalog,
        fingerprint=fingerprint, full_package_pin=full_pin)
    return result


def main():
    return 2


if __name__ == '__main__':
    raise SystemExit(main())

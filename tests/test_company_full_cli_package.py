"""Pure delivery/request controls; captured code is never executed."""
import base64
import copy
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


D = load('full_cli_delivery_under_test', 'deploy/installer/build-full-cli-package.py')
R = load('full_cli_request_under_test', 'deploy/installer/company_full_cli_request.py')
OriginalPackage = load('full_cli_original_package', 'deploy/installer/build-full-package.py')
OriginalPlan = load('full_cli_original_plan', 'deploy/installer/company_full_plan.py')
OriginalParent = load('full_cli_original_parent', 'scripts/installer_parent.py')


class Fixture:
    def __init__(self):
        self.root = ROOT / 'not-a-real-captured-source'
        self.fingerprint = 'f' * 64
        paths = set(D.LAUNCH_PATHS) | set(D.PACKAGE_PATHS) | set(D.OPERATIONAL_PATHS)
        self.files = {path: ("raise AssertionError('captured input must never execute')\n# " + path + '\n').encode()
                      for path in paths}
        self.launch = {path: self.pin(self.files[path]) for path in D.LAUNCH_PATHS}
        self.package = {path: self.pin(self.files[path]) for path in D.PACKAGE_PATHS}
        self.catalog = {path: dict(**self.pin(self.files[path]), gitMode='100644') for path in D.OPERATIONAL_PATHS}
        self.full = D.canonical(dict(schemaVersion=1, scope='FULL_INSTALLATION_COMPOSITION_ONLY',
            keyFingerprint=self.fingerprint, operationalCatalog=self.catalog,
            records={path: self.record(self.files[path]) for path in D.PACKAGE_PATHS}))
        self.full_pin = self.pin(self.full)
        self.reads = []

    def pin(self, raw):
        return dict(bytes=len(raw), sha256=D.sha(raw))

    def record(self, raw):
        return dict(**self.pin(raw), base64=base64.b64encode(raw).decode('ascii'))

    def reader(self, path, maximum):
        name = path.relative_to(self.root).as_posix()
        self.reads.append((name, maximum))
        return self.files[name]

    def arguments(self):
        return dict(launch_pins=self.launch, package_pins=self.package, operational_catalog=self.catalog,
                    fingerprint=self.fingerprint, full_package_pin=self.full_pin)

    def assemble(self, **changes):
        args = dict(self.arguments(), reader=self.reader, full_package_raw=self.full)
        args.update(changes)
        return D.assemble(self.root, **args)

    def validate(self, raw, **changes):
        args = dict(self.arguments(), delivery_pin=self.pin(raw))
        args.update(changes)
        return D.validate_delivery(raw, **args)


class DeliveryControls(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()

    def test_complete_capture_deterministic_and_never_executes_member(self):
        raw = self.f.assemble()
        value = self.f.validate(raw)
        self.assertEqual(value['launchCaptures'], {path: self.f.files[path] for path in D.LAUNCH_PATHS})
        self.assertEqual(value['fullPackage'], self.f.full)
        self.assertEqual(value['fullCaptures'], {path: self.f.files[path] for path in D.PACKAGE_PATHS})
        self.assertEqual(len(self.f.reads), 11 + 9 + 16)
        self.assertEqual([path for path, maximum in self.f.reads], [*D.LAUNCH_PATHS, *D.PACKAGE_PATHS, *D.OPERATIONAL_PATHS])
        self.assertTrue(all(maximum == len(self.f.files[path]) for path, maximum in self.f.reads))
        self.assertEqual(raw, self.f.assemble())
        self.assertLessEqual(len(raw), D.MAX_DELIVERY)

    def test_original_nine_package_and_fifteen_catalog_contract_unchanged(self):
        self.assertEqual(D.PACKAGE_PATHS, OriginalPackage.PACKAGE_PATHS)
        self.assertEqual(D.OPERATIONAL_PATHS, OriginalPackage.OPERATIONAL_PATHS)
        old = OriginalPackage.validate_package(self.f.full, package_pins=self.f.package,
            operational_catalog=self.f.catalog, fingerprint=self.f.fingerprint)
        self.assertEqual(old['scope'], 'FULL_INSTALLATION_COMPOSITION_ONLY')
        self.assertEqual(D.MAX_FULL_PACKAGE, OriginalPackage.MAX_PACKAGE_BYTES)
        self.assertEqual(D.MAX_FULL_DECODED, OriginalPackage.MAX_SOURCE_BYTES)
        self.assertIn('deploy/installer/company_full_cli_request.py', D.LAUNCH_PATHS)
        self.assertEqual(len(D.LAUNCH_PATHS), 11)

    def test_wrong_external_delivery_digest_refuses_rehashed_self_rows(self):
        raw = self.f.assemble()
        with self.assertRaises(D.FullCliPackageUnavailable):
            self.f.validate(raw, delivery_pin=dict(bytes=len(raw), sha256='0' * 64))

    def test_bad_last_launch_member_is_rejected_without_execution(self):
        raw = self.f.assemble()
        value = __import__('json').loads(raw)
        path = D.LAUNCH_PATHS[-1]
        data = b'!' + self.f.files[path][1:]
        value['launchRecords'][path]['base64'] = base64.b64encode(data).decode()
        with self.assertRaises(D.FullCliPackageUnavailable):
            self.f.validate(D.canonical(value))

    def test_external_member_pin_mismatch_denies_before_reader(self):
        pins = copy.deepcopy(self.f.launch)
        pins[D.LAUNCH_PATHS[-1]]['bytes'] = True
        with self.assertRaises(D.FullCliPackageUnavailable):
            self.f.assemble(launch_pins=pins)
        self.assertEqual(self.f.reads, [])

    def test_extra_missing_and_path_alias_launch_rows_refused(self):
        for kind in ('extra', 'missing', 'alias'):
            with self.subTest(kind=kind):
                pins = copy.deepcopy(self.f.launch)
                first = D.LAUNCH_PATHS[0]
                if kind == 'extra': pins['scripts/foreign.py'] = pins[first]
                elif kind == 'missing': del pins[first]
                else: pins['deploy/installer/../installer/company_full_cli.py'] = pins.pop(first)
                with self.assertRaises(D.FullCliPackageUnavailable): self.f.assemble(launch_pins=pins)
                self.assertEqual(self.f.reads, [])

    def test_full_package_tamper_is_refused_before_any_source_reader(self):
        changed = self.f.full[:-2] + b'!\n'
        with self.assertRaises(D.FullCliPackageUnavailable): self.f.assemble(full_package_raw=changed)
        self.assertEqual(self.f.reads, [])

    def test_full_package_schema_bool_malformed_and_extra_fields_refused(self):
        original = __import__('json').loads(self.f.full)
        for kind in ('bool', 'legacy', 'extra', 'fingerprint'):
            with self.subTest(kind=kind):
                value = copy.deepcopy(original)
                if kind == 'bool': value['schemaVersion'] = True
                elif kind == 'legacy': value['scope'] = 'FOUNDATION_ONLY'
                elif kind == 'extra': value['executionAuthorized'] = True
                else: value['keyFingerprint'] = '0' * 64
                raw = D.canonical(value)
                with self.assertRaises(D.FullCliPackageUnavailable):
                    self.f.assemble(full_package_raw=raw, full_package_pin=self.f.pin(raw))
                self.assertEqual(self.f.reads, [])

    def test_noncanonical_base64_pad_bits_are_refused(self):
        # Both encodings decode to b'a'; only YQ== is canonical.
        self.assertEqual(base64.b64decode('YR==', validate=True), b'a')
        with self.assertRaises(D.FullCliPackageUnavailable):
            D._record(dict(bytes=1, sha256=D.sha(b'a'), base64='YR=='), self.f.pin(b'a'))

    def test_duplicate_json_key_and_noncanonical_whitespace_refused(self):
        raw = self.f.assemble()
        for changed in (raw.replace(b'{', b'{"schemaVersion":1,', 1), b' ' + raw, raw[:-1]):
            with self.assertRaises(D.FullCliPackageUnavailable): self.f.validate(changed)

    def test_capture_and_aggregate_source_caps_refused_before_reader(self):
        for kind in ('member', 'total'):
            pins = copy.deepcopy(self.f.launch)
            if kind == 'member': pins[D.LAUNCH_PATHS[0]]['bytes'] = D.MAX_CAPTURE + 1
            else:
                for path in D.LAUNCH_PATHS: pins[path]['bytes'] = 30000
            with self.assertRaises(D.FullCliPackageUnavailable): self.f.assemble(launch_pins=pins)
            self.assertEqual(self.f.reads, [])

    def test_wire_size_preflight_includes_base64_and_metadata_before_reader(self):
        raw = self.f.assemble(); self.f.reads.clear()
        before = D.MAX_DELIVERY
        D.MAX_DELIVERY = len(raw) - 1  # Smaller injected policy, no capacity expansion.
        try:
            with self.assertRaises(D.FullCliPackageUnavailable): self.f.assemble()
            self.assertEqual(self.f.reads, [])
        finally: D.MAX_DELIVERY = before

    def test_catalog_modes_overlap_bytes_and_types_are_exact(self):
        for kind in ('mode', 'overlap', 'bytes'):
            catalog = copy.deepcopy(self.f.catalog)
            path = 'scripts/verify-release.py'
            if kind == 'mode': catalog[path]['gitMode'] = '100755'
            elif kind == 'overlap': catalog[path]['sha256'] = '0' * 64
            else: catalog[path]['bytes'] = float(catalog[path]['bytes'])
            with self.assertRaises(D.FullCliPackageUnavailable): self.f.assemble(operational_catalog=catalog)
            self.assertEqual(self.f.reads, [])

    def test_reader_tamper_and_stale_overlap_deny_without_output(self):
        def changed(path, maximum):
            raw = self.f.reader(path, maximum)
            return b'!' + raw[1:] if path.as_posix().endswith('scripts/verify-release.py') else raw
        with self.assertRaises(D.FullCliPackageUnavailable): self.f.assemble(reader=changed)
        self.assertTrue(self.f.reads)

    def test_overdepth_utf8_and_size_errors_use_fixed_failure(self):
        for raw in (b'{"x":' + b'[' * 1500 + b'0' + b']' * 1500 + b'}\n', b'\xff', b'x' * (D.MAX_DELIVERY + 1)):
            with self.assertRaises(D.FullCliPackageUnavailable): self.f.validate(raw)

    def test_no_reader_or_relative_root_and_cli_remain_denied(self):
        with self.assertRaises(D.FullCliPackageUnavailable): self.f.assemble(reader=None)
        with self.assertRaises(D.FullCliPackageUnavailable):
            D.assemble('relative-root', full_package_raw=self.f.full, reader=self.f.reader, **self.f.arguments())
        self.assertEqual(self.f.reads, [])
        self.assertEqual(D.main(), 2)


class RequestControls(unittest.TestCase):
    def setUp(self):
        self.request = dict(schemaVersion=1, mode='full-installation', operationId='1' * 32,
            releaseSha256='2' * 64, bundleRoot='/opt/autosoft-company/incoming/bundle',
            sourceRoot='/opt/autosoft-company/incoming/source', keyPath='/opt/autosoft-company/bootstrap/company.pem',
            dataDir='/srv/autosoft', backingFile='/srv/autosoft.luks', capacityGiB=32,
            runscVersion='20261013.1', runscSha512='3' * 128)
        self.raw = R.canonical(self.request); self.request_sha = R.sha(self.raw)

    def parse(self, value):
        raw = R.canonical(value)
        return R.validate_request(raw, request_sha256=R.sha(raw))

    def invocation(self, command='plan-stage', stage=R.STAGES[0]):
        return dict(schemaVersion=1, scope='FULL_RETENTION_CLI_INVOCATION_ONLY', command=command,
            stage=stage, requestSha256=self.request_sha, releaseSha256=self.request['releaseSha256'],
            operationId=self.request['operationId'] if stage == R.STAGES[0] else '4' * 32,
            storeOperationId=self.request['operationId'], planSha256=None if command == 'plan-stage' else '5' * 64,
            outcomeSha256='6' * 64 if command == 'verify-stage' else None,
            parent=None if command == 'plan-stage' else ['1234', '20', '21', 's-Ab1234567890', self.request_sha, stage, '7' * 64])

    def invoke(self, value):
        raw = R.canonical(value)
        return R.validate_invocation(raw, invocation_sha256=R.sha(raw), request_raw=self.raw, request_sha256=self.request_sha)

    def test_request_exactly_matches_original_planner_valid_fields(self):
        value = self.parse(self.request)
        self.assertEqual(value, dict(OriginalPlan.validate_request(value)))
        self.assertNotIn('architecture', value)

    def test_exact_request_digest_and_canonical_bytes_required(self):
        for raw, digest in ((self.raw, '0' * 64), (self.raw[:-1], R.sha(self.raw[:-1])),
                            (b' ' + self.raw, R.sha(b' ' + self.raw))):
            with self.assertRaises(R.FullCliRequestUnavailable): R.validate_request(raw, request_sha256=digest)

    def test_boolean_float_extra_field_and_wrong_mode_requests_refused(self):
        for key, val in (('schemaVersion', True), ('capacityGiB', 32.0), ('capacityGiB', True),
                         ('nativeAuthorized', True), ('mode', 'foundation-only')):
            value = dict(self.request); value[key] = val
            with self.assertRaises(R.FullCliRequestUnavailable): self.parse(value)

    def test_path_policy_does_not_loosen_for_native_or_windows_fixtures(self):
        for key, val in (('sourceRoot', '/tmp/source'), ('sourceRoot', 'D:/apps/source'),
                         ('bundleRoot', '//opt/autosoft-company/incoming/bundle'), ('keyPath', '/etc/company.pem'),
                         ('backingFile', '/opt/autosoft-company/image'), ('dataDir', '/srv/autosoft-company'),
                         ('backingFile', '/srv/autosoft/disk'), ('sourceRoot', '/opt/autosoft-company/incoming/../source')):
            value = dict(self.request); value[key] = val
            with self.assertRaises(R.FullCliRequestUnavailable): self.parse(value)
            with self.assertRaises(OriginalPlan.FullPlanUnavailable): OriginalPlan.validate_request(value)

    def test_plan_execute_verify_shapes_preserve_original_parent_abi(self):
        for stage in R.STAGES:
            for command in R.COMMANDS:
                value = self.invoke(self.invocation(command, stage))
                if command != 'plan-stage':
                    parent = OriginalParent.ParentInput.from_argv(value['parent'])
                    self.assertEqual(parent.request, self.request_sha)
                    self.assertEqual(parent.stage, stage)
        self.assertNotIn('stageAcknowledged', value)

    def test_cross_release_request_operation_and_unsupported_stage_refused(self):
        for key, val in (('releaseSha256', 'a' * 64), ('requestSha256', 'b' * 64),
                         ('storeOperationId', 'c' * 32), ('stage', 'repository-seed'), ('command', 'activate')):
            value = self.invocation(); value[key] = val
            with self.assertRaises(R.FullCliRequestUnavailable): self.invoke(value)

    def test_plan_has_no_parent_outcome_or_preclaimed_ack(self):
        for key, val in (('parent', []), ('outcomeSha256', '8' * 64), ('planSha256', '9' * 64), ('stageAcknowledged', True)):
            value = self.invocation(); value[key] = val
            with self.assertRaises(R.FullCliRequestUnavailable): self.invoke(value)

    def test_parent_false_session_duplicate_fd_wrong_binding_and_types_refused(self):
        for index, val in ((0, True), (0, '1'), (0, '01234'), (1, '21'), (1, '2'), (3, '00000000-0000-4000-8000-000000000000'),
                           (4, 'a' * 64), (5, 'foundation'), (6, 'b' * 63)):
            value = self.invocation('execute-stage'); value['parent'][index] = val
            with self.assertRaises(R.FullCliRequestUnavailable): self.invoke(value)

    def test_verify_requires_outcome_execute_refuses_premature_outcome(self):
        value = self.invocation('verify-stage'); value['outcomeSha256'] = None
        with self.assertRaises(R.FullCliRequestUnavailable): self.invoke(value)
        value = self.invocation('execute-stage'); value['outcomeSha256'] = 'a' * 64
        with self.assertRaises(R.FullCliRequestUnavailable): self.invoke(value)

    def test_invocation_oversize_overdepth_and_hash_refusal(self):
        raw = R.canonical(self.invocation())
        with self.assertRaises(R.FullCliRequestUnavailable):
            R.validate_invocation(raw, invocation_sha256='0' * 64, request_raw=self.raw, request_sha256=self.request_sha)
        for changed in (b'x' * (R.MAX_INVOCATION + 1), b'{"x":' + b'[' * 1500 + b'0' + b']' * 1500 + b'}\n'):
            with self.assertRaises(R.FullCliRequestUnavailable):
                R.validate_invocation(changed, invocation_sha256=R.sha(changed), request_raw=self.raw, request_sha256=self.request_sha)


if __name__ == '__main__':
    unittest.main()

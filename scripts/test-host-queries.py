#!/usr/bin/env python3
"""Synthetic copied-inventory/stream/reap tests; no host command or DB query."""
import ast
from copy import deepcopy
from dataclasses import replace
import importlib.util
import io
import json
from pathlib import Path
import signal
import sys
import threading
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('host_queries_test', HERE / 'host_queries.py')
Q = importlib.util.module_from_spec(spec); sys.modules[spec.name] = Q; spec.loader.exec_module(Q)
R = Q.R
DEB = b'kernel\t6.12.0-1\tamd64\tinstall ok installed\tlinux\t6.12.0-1\tno\nzlib\t1.3.2-1\tamd64\thold ok installed\tzlib\t1.3.2-1\t\n'
RPM = b'kernel-core\t0\t6.12.0\t1.el10\tx86_64\tkernel-6.12.0-1.el10.src.rpm\nzlib\t0\t1.3.2\t1.el10\tx86_64\tzlib-1.3.2-1.el10.src.rpm\n'


def capture(raw=DEB, **changes):
    value = Q.Capture(raw, b'', 0, 10, False, False, True, True, 'a' * 64)
    return replace(value, **changes)


class Backend:
    def __init__(self, family='debian'):
        self.family = family
        self.before = dict(distribution=dict(family=family, version='13' if family == 'debian' else '10.2'),
                           rpmRoot=None if family == 'debian' else 'usr/lib/sysimage/rpm',
                           files={'etc/os-release': ('opaque-source', 'opaque-identity')})
        self.bytes = {'etc/os-release': dict(sha256='b' * 64, bytes=128)}
        self.events = []
        self.outputs = [capture(DEB if family == 'debian' else RPM)] * 2
        self.fail = None
        self.source_calls = 0
        self.tool_calls = 0

    def destination(self, path): self.events.append('destination')
    def source(self):
        self.events.append('source'); self.source_calls += 1
        if self.fail == 'source-final' and self.source_calls > 1:
            raise ValueError('private-failure')
        value = deepcopy(self.before)
        if self.fail == 'source-drift' and self.source_calls > 1:
            value['files']['foreign'] = ('opaque', 'opaque')
        return value
    def hashes(self, _):
        self.events.append('hashes')
        if self.fail == 'hash-final' and self.source_calls > 1:
            raise ValueError('private-failure')
        return deepcopy(self.bytes)
    def copy(self, _):
        self.events.append('copy')
        if self.fail == 'copy': raise ValueError('private-failure')
        return dict(distribution=self.before['distribution'], rpmRoot=self.before['rpmRoot'], files=self.bytes)
    def copied(self, _, proof):
        self.events.append('copied')
        if self.fail == 'copy-final': return {'foreign': {}}
        return deepcopy(self.bytes)
    def tool(self, _):
        self.events.append('tool'); self.tool_calls += 1
        return dict(identity='identity', sha256=('d' if self.fail == 'tool-drift' and self.tool_calls > 1 else 'c') * 64)
    def run(self, argv):
        self.events.append(('command', tuple(argv)))
        return replace(self.outputs.pop(0), command_sha256=R.sha(R.canonical(argv)))
    def retain(self, _, index, value):
        self.events.append(('retain', index, value.evidence()))
        if self.fail == 'retain': raise ValueError('private-failure')


class Process:
    pid = 998877
    def __init__(self, stdout=b'ok', stderr=b'', *, waits=None, running=False):
        self.stdout = io.BytesIO(stdout); self.stderr = io.BytesIO(stderr)
        self.returncode = None if running else 0
        self.waits = list(waits or [])
        self.wait_calls = []
    def poll(self): return self.returncode
    def wait(self, timeout):
        self.wait_calls.append(timeout)
        if self.waits:
            value = self.waits.pop(0)
            if isinstance(value, BaseException): raise value
            self.returncode = value
        elif self.returncode is None:
            self.returncode = -15
        return self.returncode


class Tests(unittest.TestCase):
    def test_both_actual_decoders_generate_exact_planner_packages(self):
        deb = Q.decode_debian(DEB, R.Distribution('debian', '13'))
        self.assertEqual(deb[0]['source'], 'linux'); self.assertFalse(deb[0]['essential'])
        rpm = Q.decode_rpm(RPM, R.Distribution('rocky', '10.2'))
        self.assertEqual(rpm[0]['source'], 'kernel'); self.assertEqual(rpm[0]['source_version'], '6.12.0-1.el10')
        self.assertEqual(rpm[1]['version'], '1.3.2-1.el10')

    def test_debian_explicit_essential_and_residual_config_policy(self):
        raw = DEB.replace(b'\tno\n', b'\tyes\n') + b'residual\t\tamd64\tdeinstall ok config-files\t\t\t\n'
        rows = Q.decode_debian(raw, R.Distribution('debian', '13'))
        self.assertEqual(len(rows), 2); self.assertTrue(rows[0]['essential'])
        for status in (b'install ok unpacked', b'install reinstreq installed', b'purge ok installed', b'hold ok config-files'):
            with self.assertRaises(ValueError): Q.decode_debian(DEB.replace(b'install ok installed', status), R.Distribution('debian', '13'))

    def test_debian_source_arch_duplicate_name_and_malformed_fields_reject(self):
        for raw in (DEB.replace(b'\tlinux\t', b'\t\t'), DEB.replace(b'amd64', b'arm64'), DEB + DEB,
                    DEB.replace(b'\tno\n', b'\ttrue\n'), DEB.replace(b'\t6.12.0-1\tamd64', b'\t../bad\tamd64')):
            with self.assertRaises(ValueError): Q.decode_debian(raw, R.Distribution('debian', '13'))

    def test_rpm_unknown_source_epoch_noarch_and_multiversion_rules(self):
        self.assertEqual(len(Q.decode_rpm(RPM + RPM.splitlines(True)[0].replace(b'6.12.0', b'6.12.1'), R.Distribution('rocky', '10.2'))), 3)
        for raw in (RPM.replace(b'\t0\t', b'\t1\t'), RPM.replace(b'.src.rpm', b'.nosrc.rpm'),
                    RPM.replace(b'x86_64', b'aarch64'), RPM + RPM,
                    RPM.replace(b'kernel-6.12.0-1.el10.src.rpm', b'foreign.rpm')):
            with self.assertRaises(ValueError): Q.decode_rpm(raw, R.Distribution('rocky', '10.2'))

    def test_stream_field_line_count_encoding_and_truncation_limits(self):
        for raw in (b'', b'\xff\n', DEB[:-1], DEB.replace(b'\n', b'\r\n'), DEB + b'\n', b'x\x00\n', b'x' * (Q.STDOUT_BYTES + 1)):
            with self.assertRaises(ValueError): Q.decode_debian(raw, R.Distribution('debian', '13'))
        with patch.object(R, 'MAX_PACKAGES', 1):
            with self.assertRaises(ValueError): Q.decode_debian(DEB, R.Distribution('debian', '13'))

    def test_fixed_argv_queries_only_copied_database_no_network_or_actions(self):
        copy = Path('/protected/fixture/inventory')
        deb = Q.query_argv('debian', copy)
        rpm = Q.query_argv('rocky', copy, 'usr/lib/sysimage/rpm')
        self.assertEqual(deb[0], '/usr/bin/dpkg-query'); self.assertIn('--admindir=/protected/fixture/inventory/var/lib/dpkg', deb)
        self.assertEqual(rpm, ['/usr/bin/rpm', '--dbpath', '/protected/fixture/inventory/usr/lib/sysimage/rpm', '--query', '--all', '--queryformat', Q.RPM_FORMAT])
        for family, path, root in (('apt-get', copy, None), ('debian', copy, 'var/lib/rpm'), ('rocky', copy, '../../host'), ('debian', Path('/protected/a/../b'), None), ('debian', Path('relative'), None)):
            with self.assertRaises(ValueError): Q.query_argv(family, path, root)
        self.assertFalse(any(x in {'upgrade', 'install', '--eval', '-U', '-i', '--load-avail'} for x in deb + rpm))

    def test_inventory_calls_actual_decoders_twice_and_retains_private_proof(self):
        for family in ('debian', 'rocky'):
            backend = Backend(family)
            result = Q.HostQueries(_backend=backend).capture_inventory('/protected/fixture')
            actual = R.parse_inventory(result.inventory, Q.datetime.now(Q.timezone.utc))
            self.assertEqual(len(actual.packages), 2)
            self.assertFalse(result.apply_authorized); self.assertFalse(result.native_qualified)
            self.assertEqual(len([x for x in backend.events if isinstance(x, tuple) and x[0] == 'command']), 2)
            self.assertEqual(len(result.captures), 2)
            self.assertNotIn('private-failure', result.inventory.decode())

    def test_installed_output_drift_refuses_after_complete_initial_sample(self):
        backend = Backend(); backend.outputs[1] = capture(DEB.replace(b'1.3.2-1', b'1.3.2-2'))
        with self.assertRaisesRegex(Q.QueryUnavailable, '^host-query-unavailable$'):
            Q.HostQueries(_backend=backend).capture_inventory('/protected/fixture')
        self.assertEqual(backend.events[-4:], ['source', 'hashes', 'tool', 'copied'])

    def test_any_native_capture_fault_or_warning_is_unavailable(self):
        for change in (dict(return_code=1), dict(return_code=True), dict(reaped=False), dict(pipes_closed=False), dict(overflow=True), dict(timed_out=True), dict(stderr=b'private-warning'), dict(duration_millis=True), dict(stdout='not-bytes')):
            backend = Backend(); backend.outputs[0] = capture(**change)
            with self.assertRaisesRegex(Q.QueryUnavailable, '^host-query-unavailable$'):
                Q.HostQueries(_backend=backend).capture_inventory('/protected/fixture')
            self.assertEqual(backend.events[-4:], ['source', 'hashes', 'tool', 'copied'])

    def test_foreign_command_receipt_never_drives_planner_inventory(self):
        backend = Backend()
        backend.run = lambda argv: capture(command_sha256='f' * 64)
        with self.assertRaisesRegex(Q.QueryUnavailable, '^host-query-unavailable$'):
            Q.HostQueries(_backend=backend).capture_inventory('/protected/fixture')
        self.assertEqual(backend.events[-4:], ['source', 'hashes', 'tool', 'copied'])
        self.assertEqual(len([x for x in backend.events if isinstance(x, tuple) and x[0] == 'retain']), 1)

    def test_tool_size_is_rejected_before_binary_read(self):
        native = Q._Native()
        proof = (1, 1, 0o100755, 0, 0, 1, 32 * 1024**2 + 1, 1, 1)
        with patch.object(Q.H, 'ancestors'), patch.object(Q.H, 'ordinary_file', return_value=proof), patch.object(Q.H, 'read_file', side_effect=AssertionError('must not read oversized binary')) as read:
            with self.assertRaisesRegex(Q.QueryUnavailable, '^host-query-tool-format$'):
                native.tool('/usr/bin/rpm')
        self.assertEqual(read.call_count, 0)

    def test_every_final_reader_attempted_on_copy_decode_and_retention_errors(self):
        for failure in ('copy', 'retain', 'source-final', 'hash-final', 'source-drift', 'tool-drift', 'copy-final'):
            backend = Backend(); backend.fail = failure
            with self.assertRaises(Q.QueryUnavailable): Q.HostQueries(_backend=backend).capture_inventory('/protected/fixture')
            tail = ['source', 'hashes', 'tool'] + ([] if failure == 'copy' else ['copied'])
            self.assertEqual(backend.events[-len(tail):], tail)
        backend = Backend(); backend.outputs[0] = capture(b'corrupted-private-output\n')
        with self.assertRaises(Q.QueryUnavailable): Q.HostQueries(_backend=backend).capture_inventory('/protected/fixture')
        self.assertEqual(backend.events[-4:], ['source', 'hashes', 'tool', 'copied'])

    def test_unimplemented_authentication_and_solver_never_dispatch_or_accept_caller_proof(self):
        backend = Backend(); query = Q.HostQueries(_backend=backend)
        with self.assertRaisesRegex(Q.QueryUnavailable, '^repository-authentication-unavailable$'): query.repository_evidence()
        with self.assertRaisesRegex(Q.QueryUnavailable, '^authenticated-simulation-adapter-unavailable$'): query.simulate()
        for method in (query.repository_evidence, query.simulate):
            with self.assertRaises(TypeError): method({'signed': True})
        self.assertEqual(backend.events, [])

    def test_bounded_capture_has_exact_cleared_environment_and_separate_streams(self):
        process = Process(b'out', b'private-stderr'); arguments = []
        def popen(argv, **kwargs): arguments.append((argv, kwargs)); return process
        cap = Q._bounded_capture(['/usr/bin/dpkg-query'], _popen=popen, _signal=lambda *_: None)
        self.assertEqual(cap.stdout, b'out'); self.assertEqual(cap.stderr, b'private-stderr')
        self.assertTrue(cap.reaped); self.assertTrue(cap.pipes_closed)
        self.assertEqual(arguments[0][1]['env'], Q.ENVIRONMENT); self.assertTrue(arguments[0][1]['start_new_session'])
        self.assertNotIn('private-stderr', json.dumps(cap.evidence()))
        self.assertFalse(Q._accepted(cap))

    def test_both_stream_overflows_never_become_accepted_or_export_raw(self):
        for out, err in ((b'x' * 101, b''), (b'', b'x' * 11)):
            process = Process(out, err)
            with patch.object(Q, 'STDOUT_BYTES', 100), patch.object(Q, 'STDERR_BYTES', 10):
                cap = Q._bounded_capture(['/usr/bin/rpm'], _popen=lambda *a, **k: process, _signal=lambda *_: None)
            self.assertTrue(cap.overflow); self.assertLessEqual(len(cap.stdout), 100); self.assertLessEqual(len(cap.stderr), 10)
            self.assertFalse(Q._accepted(cap))

    def test_post_start_setup_failure_releases_and_reaps_without_exception_text(self):
        process = Process(running=True); notifications = []
        with patch.object(Q.threading, 'Thread', side_effect=RuntimeError('credential-canary')):
            cap = Q._bounded_capture(['/usr/bin/rpm'], _popen=lambda *a, **k: process, _signal=lambda *x: notifications.append(x))
        self.assertEqual(notifications, [(process.pid, signal.SIGTERM)])
        self.assertTrue(process.wait_calls); self.assertTrue(cap.reaped); self.assertFalse(Q._accepted(cap))
        self.assertNotIn('credential-canary', json.dumps(cap.evidence()))

    def test_timeout_escalates_to_kill_and_unknown_reap_is_explicit(self):
        for unknown in (False, True):
            process = Process(running=True, waits=[TimeoutError()] + ([TimeoutError()] if unknown else [-9]))
            notifications = []
            # Windows has no SIGKILL. Inject only its Linux numeric value into
            # this synthetic signal recorder; no native syscall is executed.
            with patch.object(Q, 'QUERY_SECONDS', 0), patch.object(Q.signal, 'SIGKILL', 9, create=True):
                cap = Q._bounded_capture(['/usr/bin/rpm'], _popen=lambda *a, **k: process, _signal=lambda *x: notifications.append(x))
            self.assertEqual(notifications, [(process.pid, signal.SIGTERM), (process.pid, 9)])
            self.assertTrue(cap.timed_out); self.assertEqual(cap.reaped, not unknown); self.assertFalse(Q._accepted(cap))

    def test_reader_failure_and_start_failure_fixed_evidence_never_stringify(self):
        class Poison(Exception):
            def __str__(self): raise AssertionError('must not stringify')
        cap = Q._bounded_capture(['/usr/bin/rpm'], _popen=lambda *a, **k: (_ for _ in ()).throw(Poison()), _signal=lambda *_: None)
        self.assertFalse(cap.reaped); self.assertFalse(cap.pipes_closed); self.assertFalse(Q._accepted(cap))
        process = Process()
        process.stdout = type('FailPipe', (), {'read': lambda *_: (_ for _ in ()).throw(Poison()), 'close': lambda *_: None})()
        cap = Q._bounded_capture(['/usr/bin/rpm'], _popen=lambda *a, **k: process, _signal=lambda *_: None)
        self.assertFalse(cap.pipes_closed); self.assertFalse(Q._accepted(cap))

    def test_only_new_module_test_scope_and_no_route_cli_apply_or_host_retry(self):
        tree = ast.parse((HERE / 'host_queries.py').read_bytes())
        functions = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
        self.assertFalse(functions & {'main', 'apply', 'install', 'reboot', 'upgrade'})
        self.assertNotIn('shell=True', (HERE / 'host_queries.py').read_text())
        self.assertEqual(Q.QUERY_SECONDS, 30); self.assertEqual(Q.STDERR_BYTES, 65536)
        self.assertFalse(any(isinstance(node, ast.Attribute) and node.attr == 'path' and isinstance(node.value, ast.Name) and node.value.id == 'sys' for node in ast.walk(tree)))


if __name__ == '__main__': unittest.main(verbosity=2)

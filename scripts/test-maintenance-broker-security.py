"""Actual host capture and actual caller method; synthetic child processes only."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('tested_daily_security', HERE / 'maintenance_broker_security.py')
B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)


def caller(namespace):
    tree = ast.parse((HERE / 'maintenance.py').read_bytes())
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Maintenance')
    method = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == 'app_security')
    exec(compile(ast.Module(body=[method], type_ignores=[]), str(HERE / 'maintenance.py'), 'exec'), namespace)
    return namespace['app_security']


class DailySecurityTests(unittest.TestCase):
    def test_actual_capture_returns_one_completed_small_report(self):
        command = [sys.executable, '-c', "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())"]
        result = B.read_daily_security(command, b'{"subject":"app"}')
        self.assertEqual(result, b'{"subject":"app"}')

    def test_actual_capture_denies_unbounded_child_output_before_materialization(self):
        command = [sys.executable, '-c', "import os,time;os.write(1,b'x'*5000000);time.sleep(30)"]
        with self.assertRaisesRegex(ValueError, '^' + B.FAILURE + '$'):
            B.read_daily_security(command, b'{}')

    def test_actual_capture_deadline_kills_and_reaps_only_local_child(self):
        command = [sys.executable, '-c', "import time;time.sleep(30)"]
        with patch.object(B, 'TIMEOUT', .15), self.assertRaisesRegex(ValueError, '^' + B.FAILURE + '$'):
            B.read_daily_security(command, b'{}')

    def test_actual_nonzero_child_and_missing_command_have_fixed_private_failure(self):
        for command in ([sys.executable, '-c', "import sys;sys.stderr.write('synthetic-secret');sys.exit(7)"], ['missing-synthetic-broker-command']):
            with self.assertRaisesRegex(ValueError, '^' + B.FAILURE + '$') as error:
                B.read_daily_security(command, b'{}')
            self.assertIsNone(error.exception.__cause__)
            self.assertNotIn('synthetic-secret', str(error.exception))

    def test_uncertain_reap_cannot_return_a_completed_report(self):
        spawn = B.subprocess.Popen
        def wrapped(*args, **kwargs):
            process = spawn(*args, **kwargs); wait = process.wait; count = [0]
            def uncertain(*values, **options):
                count[0] += 1
                if count[0] == 2: raise OSError('private child detail')
                return wait(*values, **options)
            process.wait = uncertain
            return process
        with patch.object(B.subprocess, 'Popen', side_effect=wrapped), self.assertRaisesRegex(ValueError, '^'+B.FAILURE+'$'):
            B.read_daily_security([sys.executable, '-c', "print('{}')"], b'{}')

    def test_partial_pipe_writes_preserve_complete_request_without_secret_logging(self):
        spawn = B.subprocess.Popen
        def wrapped(*args, **kwargs):
            self.assertIs(kwargs['stderr'], subprocess.DEVNULL)
            self.assertIs(kwargs['shell'], False)
            self.assertEqual(kwargs['bufsize'], 0)
            process = spawn(*args, **kwargs); pipe = process.stdin
            class Partial:
                def write(self, value): return pipe.write(value[:2])
                def close(self): return pipe.close()
            process.stdin = Partial()
            return process
        with patch.object(B.subprocess, 'Popen', side_effect=wrapped):
            self.assertEqual(B.read_daily_security([sys.executable,'-c',"import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())"], b'{"scope":"exact"}'), b'{"scope":"exact"}')

    def test_thread_setup_failure_reaps_child_and_preserves_fixed_failure(self):
        spawn = B.subprocess.Popen; children=[]
        def recorded(*args, **kwargs):
            process=spawn(*args, **kwargs);children.append(process);return process
        with patch.object(B.subprocess,'Popen',side_effect=recorded), patch.object(B.threading.Thread,'start',side_effect=RuntimeError('private-value')), self.assertRaisesRegex(ValueError,'^'+B.FAILURE+'$'):
            B.read_daily_security([sys.executable,'-c',"import time;time.sleep(30)"],b'{}')
        self.assertEqual(len(children),1);self.assertIsNotNone(children[0].poll())

    def test_request_bound_prevents_any_child_creation(self):
        with patch.object(B.subprocess, 'Popen') as spawn:
            for body in ('not-bytes', b'x' * (B.REQUEST_LIMIT + 1)):
                with self.assertRaises(ValueError): B.read_daily_security([], body)
            spawn.assert_not_called()

    def test_actual_method_keeps_exact_scope_and_isolation_with_protected_helper_mount(self):
        calls = []
        release = dict(appId='app-one', id='release-one', commit='a' * 40, images={'web': 'example/app@sha256:' + 'b' * 64}, other='excluded')
        report = dict(subject='app', appId=release['appId'], releaseId=release['id'], status='passed', feedUpdatedAt='2026-10-11T00:00:00Z', coverage=[])
        def capture(argv, body): calls.append((argv, body)); return json.dumps(report).encode()
        method = caller(dict(json=json, read_daily_security=capture))
        obj = types.SimpleNamespace(data=Path('/fixture/data'), root=Path('/fixture/source'), images={'platform': 'example/platform@sha256:' + 'c' * 64})
        self.assertEqual(method(obj, release), report); self.assertEqual(len(calls), 1)
        argv, body = calls[0]
        self.assertEqual(json.loads(body), dict(appId=release['appId'], releaseId=release['id'], commit=release['commit'], images=release['images']))
        self.assertEqual(argv[:12], ['docker','run','--rm','--read-only','--user=10001:10001','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=256m','--pids-limit=64','--network=autosoft_runtime','--env','NODE_EXTRA_CA_CERTS=/etc/autosoft/ca.crt'])
        self.assertEqual(argv[12:18], ['--volume', str(obj.data/'tls/ca.crt')+':/etc/autosoft/ca.crt:ro,z', '--volume', str(obj.data/'secrets/runtime/broker-token')+':/run/secrets/broker-token:ro,z', '--volume', str(obj.root/'scripts/maintenance-broker-security.mjs')+':/opt/maintenance-broker-security.mjs:ro,z'])
        self.assertEqual(argv[18:], ['-i',obj.images['platform'],'node','--import','tsx','/opt/maintenance-broker-security.mjs'])
        self.assertFalse(any('docker.sock' in arg for arg in argv))

    def test_actual_method_preserves_report_identity_status_and_one_call_failure_gates(self):
        release = dict(appId='app-one', id='release-one', commit='a'*40, images={})
        obj = types.SimpleNamespace(data=Path('/data'),root=Path('/source'),images={'platform':'image'})
        base = dict(subject='app', appId='app-one', releaseId='release-one', status='passed')
        for changes in ({'subject':'host'}, {'appId':'foreign'}, {'releaseId':'foreign'}, {'status':'clean'}):
            calls = []
            def capture(*args): calls.append(args); return json.dumps({**base, **changes}).encode()
            with self.assertRaisesRegex(ValueError, 'identity mismatch'): caller(dict(json=json,read_daily_security=capture))(obj, release)
            self.assertEqual(len(calls),1)
        for status in ('passed','failed','unavailable'):
            self.assertEqual(caller(dict(json=json,read_daily_security=lambda *args:json.dumps({**base,'status':status}).encode()))(obj,release)['status'],status)
        count = []
        def unknown(*args): count.append(args); raise ValueError(B.FAILURE)
        with self.assertRaisesRegex(ValueError,B.FAILURE): caller(dict(json=json,read_daily_security=unknown))(obj,release)
        self.assertEqual(len(count),1)

    def test_one_bounded_current_call_and_exact_transport_resource_constants(self):
        # Installed test uses semantic pins only, with no excluded-baseline dependency.
        source = (HERE/'maintenance.py').read_bytes(); tree=ast.parse(source)
        method = next(node for node in next(node for node in tree.body if isinstance(node,ast.ClassDef) and node.name=='Maintenance').body if isinstance(node,ast.FunctionDef) and node.name=='app_security')
        self.assertEqual(len([node for node in ast.walk(method) if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='read_daily_security']),1)
        self.assertFalse(any(isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='run' for node in ast.walk(method)))
        self.assertEqual(B.TIMEOUT,330);self.assertEqual(B.REPORT_LIMIT,4194304);self.assertEqual(B.REQUEST_LIMIT,65536)


if __name__ == '__main__': unittest.main()

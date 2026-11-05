#!/usr/bin/env python3
"""Contract tests: replay tooling cannot target live or unrelated MySQL storage."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from recovery_tools import canonical_binlogs, validate_candidate_container, tooling_command, table_check_command, cleanup_candidate, RecoveryCleanupUncertain, REPLAY_COMMAND, CHECK_COMMAND, HOSTS

CID = 'a' * 64
IMAGE_ID = 'sha256:' + 'b' * 64
SERVER = 'mysql@sha256:' + 'c' * 64
TOOLS = 'registry.company.example/recovery@sha256:' + 'd' * 64


class RecoveryToolTests(unittest.TestCase):
    def setUp(self):
        temporary_root = Path(__file__).resolve().parent.parent / '.local'
        temporary_root.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=temporary_root, prefix='recovery-tools-test-')
        self.addCleanup(self.temp.cleanup)
        self.candidate = Path(self.temp.name).resolve() / 'candidate'
        self.candidate.mkdir()
        self.inspection = dict(Id=CID, Image=IMAGE_ID, Name='/autosoft-chain-0123456789ab',
            Config=dict(Image=SERVER, User='999:999'), State=dict(Running=True), HostConfig=dict(NetworkMode='none', PortBindings={}, CapDrop=['ALL'], SecurityOpt=['no-new-privileges']),
            NetworkSettings=dict(Ports={'3306/tcp': None}, Networks={'none': dict(IPAddress='', GlobalIPv6Address='')}),
            Mounts=[dict(Type='bind', Source=str(self.candidate / relative), Destination=target)
                for target, relative in [('/var/lib/mysql', 'mysql'), ('/var/lib/mysql-keyring', 'mysql-keyring'), ('/etc/autosoft/tls', 'tls/mysql'), ('/run/secrets', 'secrets/mysql')]])

    def test_exact_isolated_candidate_and_fixed_tls_pipeline(self):
        self.assertEqual(validate_candidate_container(self.inspection, CID, SERVER, self.candidate, IMAGE_ID), self.candidate)
        command = tooling_command(TOOLS, CID, self.candidate.parent, ['mysql-bin.000002', 'mysql-bin.000003'])
        self.assertIn('--network=container:' + CID, command)
        self.assertIn('--pull=never', command)
        self.assertIn('--read-only', command)
        self.assertIn('--cap-drop=ALL', command)
        self.assertIn('--user=999:999', command)
        self.assertEqual(command[-2:], ['mysql-bin.000002', 'mysql-bin.000003'])
        self.assertEqual(command.count(REPLAY_COMMAND), 1)
        self.assertEqual(REPLAY_COMMAND.count('--ssl-mode=VERIFY_IDENTITY'), 2)
        self.assertEqual(REPLAY_COMMAND.count('--protocol=TCP --host=mysql'), 2)
        self.assertIn('pipefail', REPLAY_COMMAND)
        self.assertIn('--disable-log-bin', REPLAY_COMMAND)
        self.assertIn('--local-infile=0', REPLAY_COMMAND)
        self.assertNotIn('/var/lib/mysql', ' '.join(command))
        self.assertNotIn('--password', ' '.join(command))
        self.assertIn('127.0.0.1 localhost mysql', HOSTS)

    def test_wrong_container_image_namespace_and_mount_refused(self):
        alterations = [dict(Id='e' * 64), dict(Image='sha256:' + 'e' * 64), dict(Name='/autosoft-mysql-1'),
            dict(Config=dict(Image='mysql:8.4')), dict(State=dict(Running=False)),
            dict(HostConfig=dict(NetworkMode='host', PortBindings={})),
            dict(HostConfig=dict(NetworkMode='none', PortBindings={'3306/tcp': [{'HostPort': '3306'}]})),
            dict(NetworkSettings=dict(Ports={}, Networks={'none': {}, 'default': {'IPAddress': '172.17.0.3'}})),
            dict(Mounts=self.inspection['Mounts'] + [dict(Type='bind', Source='/etc', Destination='/unrelated')]),
            dict(Mounts=self.inspection['Mounts'] + [dict(Type='bind', Source=str(self.candidate), Destination='/everything')]),
            dict(Config=dict(Image=SERVER, User='0:0'))]
        for change in [dict(Privileged=True), dict(PidMode='host'), dict(IpcMode='host'), dict(CapDrop=[]), dict(SecurityOpt=[]), dict(Devices=[{'PathOnHost':'/dev/sda'}])]:
            alterations.append(dict(HostConfig={**self.inspection['HostConfig'], **change}))
        wrong_mount = copy.deepcopy(self.inspection['Mounts']); wrong_mount[0]['Source'] = str(self.candidate.parent / 'production/mysql')
        alterations.append(dict(Mounts=wrong_mount))
        for change in alterations:
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_candidate_container({**self.inspection, **change}, CID, SERVER, self.candidate, IMAGE_ID)

    def test_binary_log_arguments_cannot_escape_or_skip(self):
        for names in [[], ['../mysql-bin.000002'], ['mysql-bin.000002;id'], ['mysql-bin.000002\n'],
                      ['--password=secret'], ['mysql-bin.000002', 'mysql-bin.000004'],
                      ['mysql-bin.000002', 'mysql-bin.000002'], ['mysql-bin.2']]:
            with self.subTest(names=names), self.assertRaises(ValueError): canonical_binlogs(names)
        for image in ['mysql:8.4', TOOLS + ';id', 'company@sha256:' + 'D' * 64]:
            with self.subTest(image=image), self.assertRaises(ValueError):
                tooling_command(image, CID, self.candidate, ['mysql-bin.000002'])

    def test_table_check_is_fixed_and_equally_confined(self):
        command = table_check_command(TOOLS, CID, self.candidate.parent)
        self.assertEqual(command[-2:], [CHECK_COMMAND, 'recovery-check'])
        self.assertEqual(command[:-2], tooling_command(TOOLS, CID, self.candidate.parent, ['mysql-bin.000002'])[:-3])
        self.assertIn('mysqlcheck --defaults-file=', CHECK_COMMAND)
        self.assertIn('--ssl-mode=VERIFY_IDENTITY', CHECK_COMMAND)
        self.assertTrue(CHECK_COMMAND.endswith('--all-databases --check --skip-auto-repair'))
        self.assertNotIn('--repair', CHECK_COMMAND)
        self.assertNotIn('--auto-repair', CHECK_COMMAND)
        self.assertNotIn('/var/lib/mysql', ' '.join(command))
        for image, identifier in [('mysql:8.4', CID), (TOOLS, 'mysql-prod'), (TOOLS, CID + ';id')]:
            with self.subTest(image=image, identifier=identifier), self.assertRaises(ValueError):
                table_check_command(image, identifier, self.candidate)

    def test_cleanup_removes_original_full_id_even_after_it_has_stopped(self):
        calls=[]; record=copy.deepcopy(self.inspection); record['State']['Running']=False
        def capture(args):
            calls.append(args)
            return json.dumps([record]) if args[1]=='inspect' else ''
        cleanup_candidate(CID,SERVER,self.candidate,'autosoft-chain-0123456789ab',capture,lambda args:calls.append(args))
        self.assertIn(['docker','rm','-f',CID],calls)
        self.assertFalse(any(args[-1]=='autosoft-chain-0123456789ab' for args in calls))
        self.assertIn('--no-trunc',calls[-1])

    def test_cleanup_retains_unknown_or_replaced_container_without_name_deletion(self):
        for change in (dict(Id='e'*64),dict(Name='/autosoft-mysql-1'),dict(Config=dict(Image='mysql:latest')),dict(Mounts=[])):
            calls=[]; record={**self.inspection,**change}
            with self.subTest(change=change),self.assertRaises(RecoveryCleanupUncertain):
                cleanup_candidate(CID,SERVER,self.candidate,'autosoft-chain-0123456789ab',lambda args:json.dumps([record]),lambda args:calls.append(args))
            self.assertEqual(calls,[])
        for identifier in (None,'mysql',CID[:12]):
            with self.subTest(identifier=identifier),self.assertRaises(RecoveryCleanupUncertain):
                cleanup_candidate(identifier,SERVER,self.candidate,'autosoft-chain-0123456789ab')
        with self.assertRaises(RecoveryCleanupUncertain):
            cleanup_candidate(CID,SERVER,self.candidate,'autosoft-chain-0123456789ab',lambda args:json.dumps([self.inspection]) if args[1]=='inspect' else CID,lambda args:None)


if __name__ == '__main__':
    unittest.main()

"""No network or real credentials. Run with Python's unittest discovery."""
import importlib.util
import json
import posixpath
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('provider_preflight', Path(__file__).resolve().parents[1] / 'scripts/provider-preflight.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
KEY = 'synthetic-credential-' + 'x' * 40
CLIENT = '123456789-synthetic.apps.googleusercontent.com'
SECRET = 'synthetic-client-secret'


class Response:
    def __init__(self, status=200, data=None, headers=None, body=None):
        self.status = status
        self.body = json.dumps(data or {'data': [{'id': 'test-model'}]}).encode() if body is None else body
        self.headers = headers or {}
        self.reads = 0

    def getheader(self, key, default=None):
        return self.headers.get(key, default)

    def read(self, maximum):
        self.reads += 1
        return self.body[:maximum]


class PreflightTests(unittest.TestCase):
    def request(self, provider, response):
        calls = []
        class Connection:
            def __init__(self, host, **options):
                calls.append((host, options))
            def request(self, method, path, headers):
                calls.append((method, path, headers))
            def getresponse(self):
                return response
            def close(self):
                calls.append('closed')
        return M.check_provider(provider, KEY, Connection), calls

    def test_fixed_tls_destination_and_no_generation(self):
        result, calls = self.request('openai', Response())
        self.assertTrue(result['authenticationAccepted'])
        self.assertEqual(calls[0][0], 'api.openai.com')
        self.assertTrue(calls[0][1]['context'].check_hostname)
        self.assertEqual(calls[1][:2], ('GET', '/v1/models'))
        self.assertEqual(calls[1][2]['Authorization'], 'Bearer ' + KEY)
        self.assertFalse(result['generationTested'])
        self.assertNotIn(KEY, json.dumps(result))
        self.assertEqual(calls[-1], 'closed')

    def test_anthropic_pagination_is_not_claimed_complete(self):
        result, calls = self.request('anthropic', Response(data={'data': [{'id': 'test-model'}], 'has_more': True}))
        self.assertTrue(result['authenticationAccepted'])
        self.assertFalse(result['catalogComplete'])
        self.assertEqual(calls[1][2]['x-api-key'], KEY)
        self.assertEqual(calls[1][2]['anthropic-version'], '2023-06-01')

    def test_redirect_and_errors_never_read_or_report_body(self):
        for status in (301, 302, 307, 308, 401, 403, 429, 500):
            with self.subTest(status=status):
                response = Response(status=status, body=KEY.encode(), headers={'Location': 'https://untrusted.invalid'})
                result, calls = self.request('openai', response)
                self.assertFalse(result['authenticationAccepted'])
                self.assertEqual(response.reads, 0)
                self.assertEqual(len(calls), 3)
                self.assertNotIn(KEY, json.dumps(result))

    def test_invalid_or_oversized_receipts_fail_closed(self):
        samples = [Response(body=b'x' * (M.MAX_RESPONSE + 1)), Response(body=b'invalid'),
                   Response(data={'data': [{'id': '../escape'}]}),
                   Response(data={'data': [{'id': KEY}]}),
                   Response(data={'data': [{'id': 'same'}, {'id': 'same'}]}),
                   Response(headers={'Content-Length': '2'}),
                   Response(headers={'Content-Encoding': 'gzip'})]
        for response in samples:
            with self.subTest(response=response):
                result, _ = self.request('openai', response)
                self.assertFalse(result['authenticationAccepted'])
                self.assertEqual(result['modelIds'], [])

    def test_google_formats_are_parsed_without_shell_evaluation(self):
        formats = [json.dumps({'web': {'client_id': CLIENT, 'client_secret': SECRET}}),
                   f'GOOGLE_CLIENT_ID={CLIENT}\nGOOGLE_CLIENT_SECRET="{SECRET}"',
                   f'Client ID: {CLIENT}\nClient Secret: {SECRET}', f'{CLIENT}\n{SECRET}']
        for value in formats:
            self.assertEqual(M.google_client(value)[:2], (CLIENT, SECRET))

    def test_google_ambiguous_desktop_or_shell_values_fail(self):
        for value in [f'client_id={CLIENT}\nclient_id={CLIENT}\nclient_secret={SECRET}',
                      json.dumps({'installed': {'client_id': CLIENT, 'client_secret': SECRET}}),
                      '{"client_id":"a","client_id":"b"}',
                      f'client_id={CLIENT}\nclient_secret=$(secret-command)',
                      f'client_id={CLIENT}\nclient_secret={SECRET}\nunknown=value']:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    M.google_client(value)

    def test_report_contains_no_credential_or_client_values(self):
        with patch.object(M, 'protected_file', side_effect=lambda path: f'{CLIENT}\n{SECRET}' if path == 'google' else KEY), patch.object(M, 'check_provider', return_value={'authenticationAccepted': True}):
            result = M.preflight({'openai': 'openai', 'anthropic': 'anthropic', 'google': 'google'})
        encoded = json.dumps(result)
        for value in (KEY, CLIENT, SECRET):
            self.assertNotIn(value, encoded)
        self.assertFalse(result['google']['loginTested'])
        self.assertFalse(result['modelsQualified'])
        self.assertEqual(result['generationRequests'], 0)

    def test_file_errors_are_sanitized(self):
        with patch.object(M, 'protected_file', side_effect=ValueError(KEY)):
            result = M.preflight({'openai': 'openai', 'anthropic': 'anthropic', 'google': 'google'})
        self.assertNotIn(KEY, json.dumps(result))
        self.assertFalse(result['google']['clientConfigurationRecognized'])

    def test_one_provider_does_not_require_other_provider_or_sso_credentials(self):
        with patch.object(M, 'protected_file', return_value=KEY) as read, patch.object(M, 'check_provider', return_value={'authenticationAccepted': True}) as request:
            report = M.preflight({'openai': '/protected/openai'})
        read.assert_called_once_with('/protected/openai')
        request.assert_called_once_with('openai', KEY)
        self.assertEqual(report['providers']['anthropic']['status'], 'not-configured')
        self.assertEqual(report['google']['status'], 'not-configured')

    def filesystem(self, **changes):
        info = dict(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o600,
                    st_uid=0, st_nlink=1, st_size=len(KEY), st_mtime_ns=3, st_ctime_ns=4)
        info.update(changes)
        fake = SimpleNamespace(path=posixpath, sep='/', O_RDONLY=0, O_DIRECTORY=65536,
                               O_NOFOLLOW=131072, O_NONBLOCK=2048,
                               open=Mock(side_effect=[10, 11, 12]), close=Mock(),
                               fstat=Mock(side_effect=[SimpleNamespace(**info), SimpleNamespace(**info)]),
                               read=Mock(return_value=KEY.encode()))
        return fake

    def test_protected_files_require_root_private_regular_single_link(self):
        for changes in ({'st_uid': 1000}, {'st_mode': stat.S_IFREG | 0o644},
                        {'st_mode': stat.S_IFREG | 0o660}, {'st_mode': stat.S_IFIFO | 0o600},
                        {'st_nlink': 2}, {'st_size': 4097}, {'st_size': 0}):
            fake = self.filesystem(**changes)
            with self.subTest(changes=changes), patch.object(M, 'os', fake):
                with self.assertRaises(ValueError):
                    M.protected_file('/private/key')
                fake.read.assert_not_called()
                self.assertEqual(sorted(call.args[0] for call in fake.close.call_args_list), [10, 11, 12])

    def test_symlink_parents_and_changed_files_are_not_accepted(self):
        fake = self.filesystem()
        fake.open.side_effect = [10, OSError('linked parent')]
        with patch.object(M, 'os', fake), self.assertRaises(OSError):
            M.protected_file('/private/key')
        fake.close.assert_called_once_with(10)
        fake = self.filesystem()
        before = SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o600,
                                 st_uid=0, st_nlink=1, st_size=len(KEY), st_mtime_ns=3, st_ctime_ns=4)
        fake.fstat.side_effect = [before, SimpleNamespace(**{**vars(before), 'st_ctime_ns': 5})]
        with patch.object(M, 'os', fake), self.assertRaises(ValueError):
            M.protected_file('/private/key')

    def test_good_read_uses_no_follow_at_each_parent_and_leaf(self):
        fake = self.filesystem()
        with patch.object(M, 'os', fake):
            self.assertEqual(M.protected_file('/private/key'), KEY)
        self.assertTrue(fake.open.call_args_list[1].args[1] & fake.O_NOFOLLOW)
        self.assertTrue(fake.open.call_args_list[2].args[1] & fake.O_NOFOLLOW)
        self.assertEqual(fake.open.call_args_list[2].kwargs['dir_fd'], 11)
        for value in ('relative/key', '/private/../key', '/private//key'):
            fake = self.filesystem()
            with patch.object(M, 'os', fake), self.assertRaises(ValueError):
                M.protected_file(value)
            fake.read.assert_not_called()


if __name__ == '__main__':
    unittest.main()

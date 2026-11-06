#!/usr/bin/env python3
"""Host route/pool safety; native snapshot requires an explicitly invoked root run."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('network_host_runtime', Path(__file__).with_name('quota_runtime.py'))
Q = importlib.util.module_from_spec(spec); spec.loader.exec_module(Q)


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.addresses = [
            {'ifname': 'lo', 'addr_info': [{'family': 'inet', 'local': '127.0.0.1', 'prefixlen': 8}]},
            {'ifname': 'ens192', 'addr_info': [{'family': 'inet', 'local': '10.23.23.51', 'prefixlen': 24}]},
            {'ifname': 'docker0', 'addr_info': [{'family': 'inet', 'local': '172.17.0.1', 'prefixlen': 16}]}]
        self.routes = [{'dst': 'default', 'gateway': '10.23.23.1', 'dev': 'ens192'},
                       {'dst': '10.23.23.0/24', 'dev': 'ens192'},
                       {'type': 'local', 'dst': '10.23.23.51', 'table': 'local', 'dev': 'ens192'}]

    def snapshot(self):
        return Q.normalize_network_snapshot(json.dumps(self.addresses).encode(), json.dumps(self.routes).encode())

    def test_requires_canonical_explicit_rfc1918_pool(self):
        for good in ('10.44.0.0/16', '172.29.0.0/20', '192.168.99.0/24'):
            self.assertEqual(str(Q.app_network_pool(good)), good)
        for bad in ('', 'auto', '10.0.0.1/24', '10.0.0.0/8', '10.0.0.0/25', '100.64.0.0/16', '8.8.8.0/24', 'fd00::/16', '192.168.1.0/24\n', True):
            with self.subTest(bad=bad), self.assertRaises(ValueError):Q.app_network_pool(bad)

    def test_default_route_allowed_and_interface_networks_preserved(self):
        snapshot = self.snapshot()
        self.assertEqual(Q.validate_fresh_network_pool('10.44.0.0/16', snapshot), '10.44.0.0/16')
        self.assertIn({'name': 'ens192', 'addresses': ['10.23.23.0/24']}, snapshot['interfaces'])
        self.assertEqual(snapshot['routes'][0]['destination'], '0.0.0.0/0')

    def test_lan_and_docker_interface_overlaps_refuse(self):
        for pool in ('10.23.0.0/16', '172.17.0.0/16'):
            with self.subTest(pool=pool), self.assertRaises(ValueError):Q.validate_fresh_network_pool(pool, self.snapshot())

    def test_vpn_policy_table_and_broad_split_routes_refuse(self):
        for extra in ({'dst': '10.44.0.0/16', 'dev': 'tun0', 'table': 200},
                      {'dst': '0.0.0.0/1', 'dev': 'tun0'},
                      {'type': 'blackhole', 'dst': '10.44.0.0/16', 'table': 300}):
            with self.subTest(extra=extra):
                self.routes.append(extra)
                with self.assertRaises(ValueError):Q.validate_fresh_network_pool('10.44.0.0/16', self.snapshot())
                self.routes.pop()

    def test_multipath_routes_are_not_dropped(self):
        self.routes.append({'dst': '10.44.0.0/16', 'nexthops': [{'dev': 'tun1'}, {'dev': 'tun2'}]})
        snapshot = self.snapshot()
        self.assertEqual({route['interface'] for route in snapshot['routes'] if route['destination'] == '10.44.0.0/16'}, {'', 'tun1', 'tun2'})
        with self.assertRaises(ValueError):Q.validate_fresh_network_pool('10.44.0.0/16', snapshot)

    def test_duplicate_keys_invalid_addresses_and_unknown_json_fail_closed(self):
        good = json.dumps(self.routes).encode()
        for addresses in (b'[{"ifname":"lo","ifname":"eth0","addr_info":[]}]', b'[]', b'{}', b'null', b'NaN'):
            with self.subTest(addresses=addresses), self.assertRaises(ValueError):Q.normalize_network_snapshot(addresses, good)
        self.addresses[0]['addr_info'][0]['prefixlen'] = True
        with self.assertRaises(ValueError):self.snapshot()

    def test_duplicate_interfaces_and_bad_routes_fail_closed(self):
        original = copy.deepcopy(self.addresses)
        self.addresses.append(copy.deepcopy(self.addresses[0]))
        with self.assertRaises(ValueError):self.snapshot()
        self.addresses = original
        for route in ({'dst': 'not-a-route'}, {'dst': '::/0'}, {'dst': '10.44.0.0/16', 'dev': 'bad device'}, {'dst': '10.44.0.0/16', 'table': True}):
            self.routes.append(route)
            with self.subTest(route=route), self.assertRaises(ValueError):self.snapshot()
            self.routes.pop()

    def test_oversized_snapshot_fails_closed(self):
        with self.assertRaises(ValueError):Q.normalize_network_snapshot(b' '*(1024**2+1), json.dumps(self.routes).encode())

    def test_installer_conflict_refuses_before_writing_any_credential(self):
        fixture_spec = importlib.util.spec_from_file_location('network_wiring_fixture', Path(__file__).with_name('test-installation-wiring.py'))
        wiring = importlib.util.module_from_spec(fixture_spec); fixture_spec.loader.exec_module(wiring)
        fixture = wiring.Fixture(); fixture.final(finish=True)
        original_ask = fixture.ask
        fixture.ns['ask'] = lambda label, *args, **kwargs: '10.23.0.0/16' if label.startswith('Unused private IPv4 pool') else original_ask(label, *args, **kwargs)
        with self.assertRaises(ValueError):fixture.configure()
        self.assertEqual(fixture.secret_writes, [])
        self.assertFalse((fixture.data/'config/installation.json').exists())

    def request(self, body, authorized=True):
        helper_spec = importlib.util.spec_from_file_location('network_http_fixture', Path(__file__).with_name('quota-helper.py'))
        helper = importlib.util.module_from_spec(helper_spec); helper_spec.loader.exec_module(helper)
        helper.TOKEN = secrets.token_urlsafe(32)
        token = helper.TOKEN if authorized else secrets.token_urlsafe(32)
        client, server = socket.socketpair()
        client.settimeout(5)
        with patch.object(helper._runtime, 'host_network_snapshot', return_value=self.snapshot()) as observation:
            thread = threading.Thread(target=lambda: helper.Handler(server, ('local', 0), SimpleNamespace()))
            thread.start()
            try:
                request = ('POST /v1/network-snapshot HTTP/1.0\r\nAuthorization: Bearer '+token+'\r\nContent-Length: '+str(len(body))+'\r\n\r\n').encode()+body
                client.sendall(request)
                # The handler closes its buffered streams; close the owned socket
                # after its direct thread completes so the client receives EOF.
                thread.join(5); self.assertFalse(thread.is_alive())
                server.close()
                received = bytearray()
                while block := client.recv(4096):received.extend(block)
                return bytes(received), observation.call_count
            finally:
                client.close(); server.close(); thread.join(5)

    @unittest.skipUnless(os.name == 'posix', 'Native Unix socket HTTP boundary is qualified on Linux')
    def test_network_endpoint_requires_authentication_before_host_observation(self):
        response, calls = self.request(b'{}', authorized=False)
        self.assertTrue(response.startswith(b'HTTP/1.0 403 ')); self.assertEqual(calls, 0)

    @unittest.skipUnless(os.name == 'posix', 'Native Unix socket HTTP boundary is qualified on Linux')
    def test_network_endpoint_accepts_only_empty_object_and_never_executes_arguments(self):
        for body in (b'{"command":"ip link delete eth0"}', b'[]', b'{"a":1,"a":2}'):
            with self.subTest(body=body):
                response, calls = self.request(body)
                self.assertTrue(response.startswith(b'HTTP/1.0 503 ')); self.assertEqual(calls, 0)
        response, calls = self.request(b'{}')
        self.assertTrue(response.startswith(b'HTTP/1.0 200 ')); self.assertEqual(calls, 1)
        self.assertEqual(json.loads(response.split(b'\r\n\r\n', 1)[1]), self.snapshot())

if __name__ == '__main__':unittest.main()

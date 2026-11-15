"""Resolver generation identity covers served content, never host binds."""
import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import dns_host
import dns_render
import dns_wire


PREVIEW_A = 'app-0123456789abcdef0123456789abcdef'
PREVIEW_B = 'web-abcdef0123456789abcdef0123456789'


def _payload(**overrides):
    payload = {'names': ['b', 'a'], 'zone': 'internal.example.test',
               'identity_host': 'login.example.test',
               'cluster_gateway': '10.43.0.1', 'tailnet_gateway': '100.64.0.9',
               'artifact': 'deadbeef', 'tailnet_address': '100.64.0.1',
               'host_address': '10.44.0.1', 'previews': []}
    payload.update(overrides)
    return payload


def _render_payload(**overrides):
    payload = {'names': ['a'], 'zone': 'internal.example.test',
               'identity_host': None, 'cluster_gateway': '10.43.0.1',
               'tailnet_gateway': '100.64.0.9', 'tailnet_address': '100.64.0.1',
               'host_address': '10.44.0.1', 'nameservers': ['100.64.0.1', '100.64.0.2'],
               'upstreams': ['1.1.1.1'], 'previews': []}
    payload.update(overrides)
    return payload


class DigestTests(unittest.TestCase):
    def test_host_addresses_do_not_change_generation(self):
        first = dns_host.digest_for(_payload())
        second = dns_host.digest_for(_payload(tailnet_address='100.64.0.2',
                                              host_address='10.44.0.2'))
        self.assertEqual(first, second)

    def test_served_content_changes_generation(self):
        first = dns_host.digest_for(_payload())
        self.assertNotEqual(first, dns_host.digest_for(_payload(names=['a'])))
        self.assertNotEqual(first, dns_host.digest_for(
            _payload(cluster_gateway='10.43.0.2')))
        self.assertNotEqual(first, dns_host.digest_for(_payload(artifact='beef')))

    def test_previews_change_generation(self):
        first = dns_host.digest_for(_payload())
        self.assertNotEqual(first, dns_host.digest_for(_payload(previews=[PREVIEW_A])))

    def test_preview_order_does_not_change_generation(self):
        first = dns_host.digest_for(_payload(previews=[PREVIEW_A, PREVIEW_B]))
        second = dns_host.digest_for(_payload(previews=[PREVIEW_B, PREVIEW_A]))
        self.assertEqual(first, second)


class ValidationTests(unittest.TestCase):
    def test_previews_render_hosts_first_in_both_views(self):
        corefile = dns_render.configuration(
            _render_payload(previews=[PREVIEW_A]))['Corefile']
        self.assertEqual(corefile.count('hosts /dev/null'), 2)
        self.assertEqual(corefile.count(PREVIEW_A + '.internal.example.test'), 2)
        self.assertIn('100.64.0.9 ' + PREVIEW_A, corefile)
        self.assertIn('10.43.0.1 ' + PREVIEW_A, corefile)
        self.assertLess(corefile.index('hosts /dev/null'),
                        corefile.index('file tailnet.zone'))
        self.assertIn('fallthrough', corefile)
        self.assertIn('ttl 30', corefile)

    def test_empty_previews_render_without_hosts_stanza(self):
        corefile = dns_render.configuration(_render_payload())['Corefile']
        self.assertNotIn('hosts /dev/null', corefile)
        self.assertNotIn('fallthrough', corefile)

    def test_preview_collision_refuses_with_conflict_set(self):
        with self.assertRaisesRegex(ValueError, 'app.*collide|collide.*app'):
            dns_render.configuration(_render_payload(names=['app'], previews=['app']))
        with self.assertRaisesRegex(ValueError, 'ns1'):
            dns_render.configuration(_render_payload(previews=['ns1']))

    def test_previews_require_gateways(self):
        with self.assertRaisesRegex(ValueError, 'both gateway addresses'):
            dns_render.configuration(_render_payload(
                names=[], previews=[PREVIEW_A],
                cluster_gateway=None, tailnet_gateway=None))

    def test_invalid_preview_label_refuses(self):
        with self.assertRaisesRegex(ValueError, 'preview labels'):
            dns_render.configuration(_render_payload(previews=['BAD']))

    def test_query_parses_answer_ttl(self):
        name = b'\x03app\x08internal\x07example\x04test\x00'
        response = (struct.pack('!6H', 0x1234, 0x8400, 1, 1, 0, 0) + name
                    + struct.pack('!HH', 1, 1) + b'\xc0\x0c'
                    + struct.pack('!HHIH', 1, 1, 30, 4) + bytes((10, 43, 0, 1)))
        fake = MagicMock()
        fake.__enter__.return_value = fake
        fake.recv.return_value = response
        with patch.object(dns_wire.socket, 'socket', return_value=fake), \
                patch.object(dns_wire.secrets, 'randbelow', return_value=0x1234):
            result = dns_wire.query('127.0.0.1', 'app.internal.example.test')
        self.assertEqual(result, {'rcode': 0, 'authoritative': True,
                                  'addresses': ['10.43.0.1'], 'ttls': [30]})

    def test_private_answer_pins_ttl_thirty(self):
        good = {'rcode': 0, 'authoritative': True, 'addresses': ['10.43.0.1'],
                'ttls': [30]}
        with patch.object(dns_wire, 'query', return_value=good):
            dns_wire.private_answer('127.0.0.1', 'a.internal.example.test', '10.43.0.1')
        with patch.object(dns_wire, 'query', return_value=dict(good, ttls=[29])):
            with self.assertRaises(RuntimeError):
                dns_wire.private_answer('127.0.0.1', 'a.internal.example.test',
                                        '10.43.0.1')

    def test_nodata_answer_pins_empty_ttls(self):
        nodata = {'rcode': 0, 'authoritative': True, 'addresses': [], 'ttls': [],
                  'answer_count': 0}
        with patch.object(dns_wire, 'query', return_value=nodata):
            dns_wire.nodata_answer('127.0.0.1', PREVIEW_A + '.internal.example.test')

    def test_battery_wires_preview_answers_on_both_views(self):
        payload = _payload(previews=[PREVIEW_A])
        expected = PREVIEW_A + '.internal.example.test'
        with patch.object(dns_host, 'private_answer') as private, \
                patch.object(dns_host, 'nodata_answer') as nodata, \
                patch.object(dns_host, 'absent_answer'), \
                patch.object(dns_host, 'query',
                             return_value={'addresses': ['1.2.3.4']}):
            dns_host.validate_answers(payload)
        preview_private = [call for call in private.call_args_list
                           if call.args[1] == expected]
        self.assertEqual(len(preview_private), 4)
        self.assertEqual(nodata.call_count, 4)
        for call in nodata.call_args_list:
            self.assertEqual(call.args[1], expected)

    def test_adopt_inherits_previews(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state / 'inputs.json').write_text(json.dumps(_payload(previews=[PREVIEW_A])))
            with patch.object(dns_host, 'STATE', state):
                merged = dns_host.adopt({'zone': None, 'names': None, 'previews': None,
                                         'identity_host': None, 'cluster_gateway': None,
                                         'tailnet_gateway': None})
                self.assertEqual(merged['previews'], [PREVIEW_A])
                fresh = dns_host.adopt({'zone': 'internal.example.test', 'names': [],
                                        'identity_host': None, 'cluster_gateway': None,
                                        'tailnet_gateway': None})
                self.assertEqual(fresh['previews'], [PREVIEW_A])
            empty = Path(directory, 'missing')
            with patch.object(dns_host, 'STATE', empty):
                with self.assertRaisesRegex(ValueError, 'both gateway addresses'):
                    dns_host.adopt({'zone': None, 'names': [], 'previews': [PREVIEW_A],
                                    'identity_host': None, 'cluster_gateway': None,
                                    'tailnet_gateway': None})


class _UntouchedResolver:
    def is_symlink(self):
        raise AssertionError('resolver state must not be read')

    def read_text(self):
        raise AssertionError('resolver state must not be read')


class _ReachedResolver:
    def is_symlink(self):
        return False

    def read_text(self):
        raise RuntimeError('resolver read attempted')


class BinaryTests(unittest.TestCase):
    content = b'fake-coredns-elf'

    def _setup(self, root, artifact):
        binary = root / 'coredns'
        binary.write_bytes(self.content)
        state = root / 'state'
        state.mkdir()
        payload = _payload(artifact=artifact)
        (state / 'inputs.json').write_text(json.dumps(payload))
        return binary, state, payload

    def test_mismatch_refuses_before_resolver_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary, state, payload = self._setup(root, '0' * 64)
            with patch.object(dns_host, 'STATE', state), \
                    patch.object(dns_host, 'BINARY', binary), \
                    patch.object(dns_host, 'RESOLVER', _UntouchedResolver()):
                with self.assertRaisesRegex(RuntimeError, 'pinned checksum'):
                    dns_host.configure(payload)
            self.assertEqual([path.name for path in sorted(state.iterdir())],
                             ['inputs.json'])
            self.assertEqual(json.loads((state / 'inputs.json').read_text()), payload)

    def test_match_proceeds_to_resolver_state(self):
        digest = hashlib.sha256(self.content).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary, state, payload = self._setup(root, digest)
            with patch.object(dns_host, 'STATE', state), \
                    patch.object(dns_host, 'BINARY', binary), \
                    patch.object(dns_host, 'RESOLVER', _ReachedResolver()):
                with self.assertRaisesRegex(RuntimeError, 'resolver read attempted'):
                    dns_host.configure(payload)

    def test_symlink_is_resolved_before_hashing(self):
        digest = hashlib.sha256(self.content).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'target'
            target.write_bytes(self.content)
            link = MagicMock()
            link.resolve.return_value = target
            state = root / 'state'
            state.mkdir()
            payload = _payload(artifact=digest)
            (state / 'inputs.json').write_text(json.dumps(payload))
            with patch.object(dns_host, 'STATE', state), \
                    patch.object(dns_host, 'BINARY', link), \
                    patch.object(dns_host, 'RESOLVER', _ReachedResolver()):
                with self.assertRaisesRegex(RuntimeError, 'resolver read attempted'):
                    dns_host.configure(payload)
            link.resolve.assert_called_once_with()

    def test_missing_binary_refuses_before_resolver_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, state, payload = self._setup(root, '0' * 64)
            with patch.object(dns_host, 'STATE', state), \
                    patch.object(dns_host, 'BINARY', root / 'absent'), \
                    patch.object(dns_host, 'RESOLVER', _UntouchedResolver()):
                with self.assertRaises(OSError):
                    dns_host.configure(payload)
            self.assertEqual([path.name for path in sorted(state.iterdir())],
                             ['inputs.json'])


if __name__ == '__main__':
    unittest.main()

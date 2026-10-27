"""Offline native custody checks; the official binary is read only as data."""
import copy
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import ssl
import tarfile
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import yaml

from playbooks.k3s.files import native_custody as native


class NativeCustodyTests(unittest.TestCase):
    def unit(self):
        return '''[Unit]
Description=Lightweight Kubernetes
Documentation=https://k3s.io
Wants=network-online.target
After=network-online.target
[Install]
WantedBy=multi-user.target
[Service]
Type=notify
EnvironmentFile=-/etc/default/%N
EnvironmentFile=-/etc/sysconfig/%N
EnvironmentFile=-/etc/systemd/system/k3s.service.env
KillMode=process
Delegate=yes
User=root
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
TimeoutStartSec=0
Restart=always
RestartSec=5s
ExecStartPre=-/sbin/modprobe br_netfilter
ExecStartPre=-/sbin/modprobe overlay
ExecStart=/usr/local/bin/k3s server
'''

    def flags(self):
        return {'apiVersion': 'config.k8s.io/v1beta1', 'kind': 'Flagz', 'metadata': {'name': 'apiserver'},
                'flags': {'audit-log-path': '', 'audit-policy-file': '', 'audit-webhook-config-file': '',
                          'v': '0', 'vmodule': '', 'profiling': 'false', 'debug-socket-path': ''}}

    def library(self):
        # Slim check image strips changelog docs. This boundary qualifies data parsing only.
        return ctypes.CDLL('/usr/lib/x86_64-linux-gnu/libzstd.so.1')

    def archive(self, *, link='k3s', extra=None):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            item = tarfile.TarInfo('./bin/k3s'); item.size = 12
            archive.addfile(item, io.BytesIO(b'native-core\n'))
            for name in ('kubectl', 'k3s-server'):
                item = tarfile.TarInfo('./bin/'+name); item.type = tarfile.SYMTYPE; item.linkname = link
                archive.addfile(item)
            if extra is not None: archive.addfile(extra)
        raw = stream.getvalue(); library = self.library()
        library.ZSTD_compressBound.argtypes = [ctypes.c_size_t]; library.ZSTD_compressBound.restype = ctypes.c_size_t
        library.ZSTD_compress.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        library.ZSTD_compress.restype = ctypes.c_size_t
        target = ctypes.create_string_buffer(library.ZSTD_compressBound(len(raw)))
        size = library.ZSTD_compress(target, len(target), ctypes.create_string_buffer(raw), len(raw), 1)
        frame = target.raw[:size]
        return hashlib.sha256(frame).hexdigest().encode()+b'.tar.zst\0'+frame

    def derive(self, data, *, expected=None, deadline=None):
        with tempfile.TemporaryFile() as stream:
            stream.write(data); stream.flush()
            return native.derive(stream, expected or hashlib.sha256(data).hexdigest(), self.library(), deadline or time.monotonic()+10)

    def test_authenticated_archive_and_refusal_of_wrong_or_ambiguous_layout(self):
        data = self.archive()
        self.assertEqual(self.derive(data)['core'], hashlib.sha256(b'native-core\n').hexdigest())
        for bad in (data+data, data[:-7], b'0'*64+b'.tar.zst'+data, data+b'\x28\xb5\x2f\xfd'*33, self.archive(link='other')):
            with self.subTest(size=len(bad)), self.assertRaises(ValueError): self.derive(bad)
        for kind in (tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.REGTYPE):
            item = tarfile.TarInfo('../outside'); item.type = kind
            with self.assertRaises(ValueError): self.derive(self.archive(extra=item))
        with self.assertRaises(ValueError): self.derive(data, expected='0'*64)
        with self.assertRaises(ValueError): self.derive(data, deadline=time.monotonic()-1)

    @unittest.skipUnless(Path('/artifacts/k3s').is_file(), 'Explicit official data-only artifact not mounted')
    def test_genuine_pinned_artifact_derivation_and_pretoken_budget(self):
        pin = yaml.safe_load(Path(__file__).parents[1].joinpath('vars.yml').read_text())['k3s_binaries']['x86_64']['sha256']
        started = time.monotonic()
        with Path('/artifacts/k3s').open('rb') as stream:
            result = native.derive(stream, pin, self.library(), started+50)
        elapsed = time.monotonic()-started
        self.assertEqual(result['links'], {'bin/kubectl': 'k3s', 'bin/k3s-server': 'k3s'})
        self.assertRegex(result['core'], '^[a-f0-9]{64}$')
        self.assertLess(elapsed, 15, 'Data-only derivation consumes the pretoken margin')
        print('Official DATA-only derivation seconds:', round(elapsed, 3), flush=True)

    def test_flagz_requires_exact_native_schema_types_and_closed_audit_debug_paths(self):
        value = self.flags(); self.assertEqual(native.flag_policy(json.dumps(value)), value)
        changes = [lambda x: x.update(kind='Other'), lambda x: x.update(apiVersion='config.k8s.io/v1alpha1'),
                   lambda x: x.update(metadata={'name': 'kube-apiserver'}), lambda x: x.update(extra=True),
                   lambda x: x.update(flags=[])]
        for key in value['flags']:
            changes.extend((lambda x,k=key: x['flags'].pop(k), lambda x,k=key: x['flags'].update({k: 'CLASSIFIED'}),
                            lambda x,k=key: x['flags'].update({k: False}), lambda x,k=key: x['flags'].update({k: 'enabled'})))
        for change in changes:
            bad = copy.deepcopy(value); change(bad)
            with self.assertRaises(ValueError): native.flag_policy(json.dumps(bad))
        with self.assertRaises(ValueError): native.flag_policy('{"kind":"Flagz","kind":"Flagz"}')
        with self.assertRaises(ValueError): native.flag_policy('plain text audit-log-path=')

    def test_production_library_validator_requires_native_package_and_no_loader_override(self):
        directory = Path('/usr/lib/x86_64-linux-gnu'); resolved = directory/'libzstd.so.1.5.7'
        info = Mock(st_uid=0, st_mode=0o755, st_dev=1, st_ino=2, st_size=100, st_mtime_ns=1, st_ctime_ns=1)
        library = Mock(); library.ZSTD_versionNumber.return_value = 10507
        with patch.dict(os.environ, {}, clear=True), patch.object(native.platform, 'machine', return_value='x86_64'), \
                patch.object(Path, 'resolve', return_value=resolved), patch.object(Path, 'stat', return_value=info), \
                patch.object(Path, 'lstat', return_value=info), patch.object(Path, 'exists', return_value=False), \
                patch.object(Path, 'open', side_effect=lambda *a,**k: io.BytesIO(('0 1 2 3 4 '+str(resolved)+'\n').encode())), \
                patch.object(native.ctypes, 'CDLL', return_value=library) as load:
            with patch.object(native, 'run', side_effect=['libzstd1:amd64: '+str(resolved), '']):
                self.assertIs(native.trusted_library(time.monotonic()+5), library)
            for values in (['foreign: '+str(resolved)], ['libzstd1:amd64: '+str(resolved), 'changed library']):
                with patch.object(native, 'run', side_effect=values), self.assertRaises(ValueError): native.trusted_library(time.monotonic()+5)
            for key in ('LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT'):
                with patch.dict(os.environ, {key: 'foreign'}), self.assertRaises(ValueError): native.trusted_library(time.monotonic()+5)
            with patch.object(Path, 'resolve', return_value=Path('/tmp/libzstd.so.1.5.7')), self.assertRaises(ValueError):
                native.trusted_library(time.monotonic()+5)
        for raw in (b'', b'0 1 2 3 4 /tmp/libzstd.so.1.5.7\n', ('0 1 2 3 4 '+str(resolved)+' (deleted)\n').encode()):
            with self.assertRaises(ValueError):native.loaded_library(raw,str(resolved))

    def test_descriptors_refuse_symlinks_writable_files_and_mid_session_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'core'; path.write_bytes(b'native'); path.chmod(0o600)
            with native.opened(path, 100) as stream:
                before = native.identity(os.fstat(stream.fileno()))
                path.write_bytes(b'changed')
                with self.assertRaises(ValueError): native.unchanged(stream, path, before)
            path.chmod(0o666)
            with self.assertRaises(ValueError): native.opened(path, 100)
            path.chmod(0o600); link = Path(directory)/'link'; link.symlink_to(path)
            with self.assertRaises(OSError): native.opened(link, 100)

    def test_dispatch_refuses_client_or_server_shadow_and_wrong_native_link(self):
        session = native.Session(time.monotonic()+5); session.base = '/native'
        directory = Mock(st_mode=0o40755, st_uid=0, st_dev=1, st_ino=2)
        link = Mock(st_mode=0o120777, st_uid=0, st_dev=1, st_ino=3, st_mtime_ns=1, st_ctime_ns=1)
        with patch.object(Path, 'lstat', autospec=True, side_effect=lambda p: directory if p.name=='cni' else link), \
                patch.object(native.os.path, 'lexists', return_value=False), patch.object(native.os, 'readlink', return_value='k3s'):
            self.assertIn('kubectl', session.dispatch())
            with patch.object(native.os.path, 'lexists', return_value=True), self.assertRaises(ValueError): session.dispatch()
            with patch.object(native.os, 'readlink', return_value='foreign'), self.assertRaises(ValueError): session.dispatch()

    def test_native_unit_config_process_and_environment_rechecked_within_session(self):
        properties = {'ExecStart': '{ path=/usr/local/bin/k3s ; argv[]=/usr/local/bin/k3s server ; }',
                      'MainPID': '500', 'FragmentPath': '/etc/systemd/system/k3s.service',
                      'DropInPaths': '/etc/systemd/system/k3s.service.d/10-cloudlab-network.conf',
                      'Environment': '', 'NeedDaemonReload': 'no'}
        environment_files = ('/etc/default/k3s', '/etc/sysconfig/k3s', '/etc/systemd/system/k3s.service.env')
        def observation():
            return '\n'.join([k+'='+v for k,v in properties.items()] +
                             ['EnvironmentFiles='+p+' (ignore_errors=yes)' for p in environment_files])+'\n'
        files = {'/etc/systemd/system/k3s.service': self.unit().encode(),
                 properties['DropInPaths']: b'[Unit]\nRequires=wg-quick@wg0.service cloudlab-firewall.service\nAfter=wg-quick@wg0.service cloudlab-firewall.service\n',
                 '/etc/rancher/k3s/config.yaml': b'write-kubeconfig-mode: "0600"\n',
                 '/etc/rancher/k3s/k3s.yaml': json.dumps({'clusters': [{'name': 'default', 'cluster': {}}],
                     'users': [{'name': 'default', 'user': {}}], 'contexts': [{'name': 'default',
                     'context': {'cluster': 'default', 'user': 'default'}}], 'current-context': 'default'}).encode()}
        environment = [b'PATH=/usr/bin\0']; title = [b'/usr/local/bin/k3s server\0']
        with tempfile.TemporaryFile() as core:
            core.write(b'core');core.flush()
            session = native.Session(time.monotonic()+30); session.core = core; session.base = '/native'
            with patch.object(native, 'run', side_effect=lambda *args: observation()) as show, \
                    patch.object(session, 'read', side_effect=lambda p: files[str(p)]) as read, \
                    patch.object(session, 'effective_flags', side_effect=lambda c: native.flag_policy(json.dumps(self.flags()))) as api, \
                    patch.object(session, 'dispatch', return_value={}), patch.object(native.os.path, 'lexists', return_value=False) as optional, \
                    patch.object(Path, 'exists', return_value=False), \
                    patch.object(Path, 'resolve', return_value=Path('/native/bin/k3s')), \
                    patch.object(Path, 'read_text', return_value='500 (k3s) '+' '.join(['0']*19+['123'])), \
                    patch.object(Path, 'read_bytes', side_effect=lambda: title[0]), \
                    patch.object(Path, 'open', autospec=True, side_effect=lambda p,*a,**k: io.BytesIO(environment[0]) if p.name=='environ' else
                        io.BytesIO(title[0]) if p.name=='cmdline' else os.fdopen(os.dup(core.fileno()),'rb')):
                baseline = session.observe(); session.initial = baseline
                self.assertEqual(show.call_count,2)
                self.assertEqual(show.call_args_list[0],show.call_args_list[1])
                self.assertEqual(session.observe(), baseline)
                rows=observation().splitlines(); scalar_rows=rows[:len(properties)]; env_rows=rows[len(properties):]
                invalid=[rows+['Unknown=value'], rows+['malformed'], rows+[''], rows[:2]+['']+rows[2:]]
                for row in scalar_rows:
                    invalid.extend(([value for value in rows if value!=row], rows+[row],
                                    [row.partition('=')[0]+'=hidden']+rows))
                for index,row in enumerate(env_rows):
                    invalid.extend((scalar_rows+env_rows[:index]+env_rows[index+1:],
                                    scalar_rows+env_rows+[row],
                                    scalar_rows+[value.replace('ignore_errors=yes','ignore_errors=no') if value==row else value for value in env_rows],
                                    scalar_rows+[value+' trailing' if value==row else value for value in env_rows]))
                invalid.extend((scalar_rows+env_rows[::-1],scalar_rows+[env_rows[1],env_rows[0],env_rows[2]],
                                scalar_rows+['EnvironmentFiles='+' '.join(row.split('=',1)[1] for row in env_rows)],
                                scalar_rows+env_rows+['EnvironmentFiles=/unknown (ignore_errors=yes)'],
                                [row+'\r' for row in rows]))
                for bad in invalid:
                    read.reset_mock();api.reset_mock();optional.reset_mock()
                    with self.subTest(rows=bad),patch.object(native,'run',return_value='\n'.join(bad)+'\n'),self.assertRaises(ValueError):
                        session.observe()
                    read.assert_not_called();api.assert_not_called()
                    self.assertFalse(any(str(call.args[0]) in environment_files for call in optional.call_args_list))
                changed=rows.copy();changed[0],changed[1]=changed[1],changed[0]
                with patch.object(native,'run',side_effect=[observation(),'\n'.join(changed)+'\n']),self.assertRaises(ValueError):
                    session.observe()
                for key, wrong in (('MainPID', '501'), ('DropInPaths', '/foreign'), ('Environment', 'LD_PRELOAD=foreign'),
                                   ('ExecStart', '{ path=/wrapper ; argv[]=/wrapper ; }')):
                    original = properties[key]; properties[key] = wrong
                    with self.subTest(key=key), self.assertRaises(ValueError): session.observe()
                    properties[key] = original
                for key in (b'HTTP_PROXY', b'K3S_CONFIG_FILE', b'LD_AUDIT'):
                    environment[0] = key+b'=foreign\0'
                    with self.assertRaises(ValueError): session.observe()
                environment[0] = b'PATH=/usr/bin\0'
                for path, wrong in (('/etc/rancher/k3s/config.yaml', b'audit-policy-file: foreign\n'),
                                    ('/etc/systemd/system/k3s.service', self.unit().replace('server\n','server --debug\n').encode())):
                    original = files[path]; files[path] = wrong
                    with self.assertRaises(ValueError): session.observe()
                    files[path] = original
                title[0] = b'unknown server\0'
                with self.assertRaises(ValueError): session.observe()
                title[0] = b'/usr/local/bin/k3s server\0'
                with patch.object(session, 'effective_flags', return_value=dict(self.flags(), extra='drift')), self.assertRaises(ValueError): session.observe()

    def test_flagz_transport_uses_verified_tls_no_proxy_no_redirect_and_bounded_native_input(self):
        session = native.Session(time.monotonic()+5)
        ca, cert, key = b'ca', b'certificate', b'key'
        import base64
        config = {'clusters': [{'cluster': {'server': 'https://127.0.0.1:6443', 'certificate-authority-data': base64.b64encode(ca).decode()}}],
                  'users': [{'user': {'client-certificate-data': base64.b64encode(cert).decode(), 'client-key-data': base64.b64encode(key).decode()}}]}
        response = Mock(status=200); response.geturl.return_value = 'https://127.0.0.1:6443/flagz'
        response.read.return_value = json.dumps(self.flags()).encode(); response.__enter__ = Mock(return_value=response); response.__exit__ = Mock()
        context = Mock(); context.check_hostname = True; context.verify_mode = ssl.CERT_REQUIRED
        proxy = Mock(); opener = Mock(); opener.open.return_value = response
        with patch.object(session, 'read', side_effect=lambda p: ca if p.endswith('server-ca.crt') else cert if p.endswith('.crt') else key), \
                patch.object(session, 'hold', return_value=Mock(fileno=Mock(return_value=7))), \
                patch.object(native.os, 'fstat', return_value=Mock(st_mode=0o600)), \
                patch.object(native.ssl, 'create_default_context', return_value=context) as tls, \
                patch.object(native.urllib.request, 'ProxyHandler', return_value=proxy) as proxy_factory, \
                patch.object(native.urllib.request, 'build_opener', return_value=opener) as build:
            self.assertEqual(session.effective_flags(config), self.flags())
            tls.assert_called_once_with(cadata='ca'); proxy_factory.assert_called_once_with({})
            self.assertTrue(any(isinstance(item, native.NoRedirect) for item in build.call_args.args))
            self.assertEqual(opener.open.call_args.args[0].headers['Accept'], 'application/json;v=v1beta1;g=config.k8s.io;as=Flagz')
            self.assertEqual(response.read.call_args.args, (262145,))
            for wrong in (b'x'*262145, b'{"flags":{}}'):
                response.read.return_value = wrong
                with self.assertRaises(ValueError): session.effective_flags(config)
            opener.open.side_effect = ssl.SSLError('untrusted')
            with self.assertRaises(ssl.SSLError): session.effective_flags(config)
        with self.assertRaises(ValueError): native.NoRedirect().redirect_request(None, None, None, None, None, None)

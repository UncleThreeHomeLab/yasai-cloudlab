"""Offline adversarial provenance, atomic receipt and actual startup-shell guards."""
import copy
import hashlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from playbooks.observability.tests import lifecycle_stack_preflight as preflight

ID = 'a' * 64
PROJECT = 'obs-lifecycle-stack-preflight-test'


def inspected(now):
    source, startup = preflight.canonical_startup()
    moment = datetime.fromtimestamp(now - 1, timezone.utc).isoformat().replace('+00:00', 'Z')
    names = {target: str(index) * 64 for index, target in enumerate(sorted(preflight.ANONYMOUS), 1)}
    names['/fixture'] = PROJECT + '_credentials'
    mounts, volumes = [], []
    for target, name in names.items():
        location = '/var/lib/docker/volumes/' + name + '/_data'
        mounts.append({'Type': 'volume', 'Name': name, 'Source': location, 'Destination': target,
                       'Driver': 'local', 'Mode': 'rw' if target == '/fixture' else '', 'RW': True, 'Propagation': ''})
        labels = ({'cloudlab.io/purpose': preflight.PURPOSE, 'com.docker.compose.project': PROJECT,
                   'com.docker.compose.volume': 'credentials', 'com.docker.compose.version': '2.24.6'}
                  if target == '/fixture' else {})
        volumes.append({'Name': name, 'Driver': 'local', 'Scope': 'local', 'Options': None,
                        'Mountpoint': location, 'Labels': labels, 'CreatedAt': moment})
    node = {'Id': ID, 'Name': '/' + PROJECT + '-cluster-1', 'Image': 'sha256:' + 'f' * 64,
        'Created': moment, 'RestartCount': 0, 'Path': '/bin/sh', 'Args': ['-c', startup[0]],
        'State': {'Status': 'created', 'Running': False, 'Paused': False, 'Restarting': False, 'OOMKilled': False,
                  'Dead': False, 'Pid': 0, 'ExitCode': 0, 'Error': '', 'StartedAt': '0001-01-01T00:00:00Z',
                  'FinishedAt': '0001-01-01T00:00:00Z'},
        'Config': {'Image': source['image'], 'Entrypoint': source['entrypoint'], 'Cmd': startup,
            'Hostname': ID[:12], 'Domainname': '', 'User': '', 'WorkingDir': '/', 'Tty': False,
            'OpenStdin': False, 'StdinOnce': False, 'Env': sorted(preflight.BASE_ENV | {'FIXTURE_PROJECT=' + PROJECT}),
            'Volumes': {target: {} for target in preflight.ANONYMOUS | {'/var/lib/rancher/k3s'}}, 'Labels': {
                'com.docker.compose.project': PROJECT, 'com.docker.compose.service': 'cluster',
                'cloudlab.io/purpose': preflight.PURPOSE, 'com.docker.compose.container-number': '1',
                'com.docker.compose.oneoff': 'False'}},
        'HostConfig': {'Privileged': True, 'ReadonlyRootfs': False, 'Memory': 16 * 1024**3,
            'NanoCpus': 6 * 10**9, 'CpuShares': 0, 'CpuPeriod': 0, 'CpuQuota': 0, 'CpuRealtimePeriod': 0,
            'CpuRealtimeRuntime': 0, 'MemoryReservation': 0, 'BlkioWeight': 0, 'CpusetCpus': '', 'CpusetMems': '',
            'MemorySwap': 0, 'PidsLimit': None, 'OomKillDisable': None, 'OomScoreAdj': 0,
            'ShmSize': 64 * 1024**2, 'Runtime': 'runc', 'PidMode': '', 'UTSMode': '',
            'UsernsMode': '', 'IpcMode': 'private', 'CgroupnsMode': 'private', 'PublishAllPorts': False,
            'PortBindings': {}, 'NetworkMode': PROJECT + '_fixture', 'Tmpfs': {path: '' for path in preflight.TMPFS},
            'Binds': [PROJECT + '_credentials:/fixture:rw']},
        'Mounts': mounts, 'NetworkSettings': {'Ports': {}, 'Networks': {
            PROJECT + '_' + name: {'IPAMConfig': {'IPv4Address': address}, 'Aliases': [PROJECT + '-cluster-1', 'cluster']}
            for name, address in [('fixture', '10.245.239.2'), ('image_downloads', '10.245.240.2')]}}}
    return [node, *volumes]


class ReducedProfileTests(unittest.TestCase):
    def test_only_bounded_resources_and_distinct_network_priorities_change(self):
        raw = preflight.COMPOSE.with_name('compose.lifecycle-controller.yaml').read_bytes()
        changes = (
            (b'    cpus: 4\n    mem_limit: 8g\n', b''),
            (b'fixture: {ipv4_address: 10.245.237.2, priority: 100}', b'fixture: {ipv4_address: 10.245.237.2}'),
            (b'image_downloads: {ipv4_address: 10.245.238.2, priority: 0}', b'image_downloads: {ipv4_address: 10.245.238.2}'))
        def accepted(candidate):
            for added, previous in changes:
                if candidate.count(added) != 1: return False
                candidate = candidate.replace(added, previous, 1)
            return hashlib.sha256(candidate).hexdigest() == '0ddb394303e39f37c2460579ba5f62e62e5d6751b46e0089061fa239b44d2e10'
        self.assertTrue(accepted(raw))
        for before, after in ((b'priority: 100', b'priority: 0'), (b'priority: 0}', b'priority: 100}'),
                              (b'priority: 100', b'priority: 99'), (b'cpus: 4', b'cpus: 5'),
                              (b'mem_limit: 8g', b'mem_limit: 9g'),
                              (b'--node-ip=10.245.237.2', b'--node-ip=10.245.237.3'),
                              (b'privileged: true', b'privileged: false')):
            with self.subTest(change=before):
                self.assertNotEqual(raw.replace(before, after), raw)
                self.assertFalse(accepted(raw.replace(before, after)))


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        self.objects = inspected(self.now)

    def validate(self, objects=None):
        return preflight.validate(json.dumps(self.objects if objects is None else objects).encode(), ID, PROJECT, self.now)

    def test_created_complete_native_inspect_accepts_legitimate_named_volume_bind(self):
        result = self.validate()
        self.assertEqual(result['id'], ID)
        self.assertEqual(result['hostname'], ID[:12])
        self.assertEqual(result['project'], PROJECT)

    def test_fixture_primary_and_exact_typed_network_priorities_are_required(self):
        objects = copy.deepcopy(self.objects)
        objects[0]['HostConfig']['NetworkMode'] = PROJECT + '_image_downloads'
        with self.assertRaises(preflight.Refusal):
            self.validate(objects)
        source, startup = preflight.canonical_startup()
        self.assertEqual(source['networks'], {
            'fixture': {'ipv4_address': '10.245.239.2', 'priority': 100},
            'image_downloads': {'ipv4_address': '10.245.240.2', 'priority': 0}})
        for fixture_priority, download_priority in ((0, 0), (100, 100), (0, 100), (99, 0), (100, False), (100.0, 0)):
            bad = copy.deepcopy(source)
            bad['networks']['fixture']['priority'] = fixture_priority
            bad['networks']['image_downloads']['priority'] = download_priority
            with self.subTest(priorities=(fixture_priority, download_priority)), \
                    patch.object(preflight, 'canonical_startup', return_value=(bad, startup)), self.assertRaises(preflight.Refusal):
                self.validate()

    def test_duplicate_trailing_nonfinite_oversized_and_partial_inputs_refuse(self):
        raw = json.dumps(self.objects).encode()
        bad = [raw + b' true', raw + raw, b'[]', b'{}', b'\xff', b' ' * (preflight.MAX_INPUT + 1),
               raw.replace(b'"RestartCount": 0', b'"RestartCount": 0, "RestartCount": 0'),
               raw.replace(b'"MemorySwap": 0', b'"MemorySwap": NaN'), json.dumps(self.objects[:-1]).encode()]
        for data in bad:
            with self.subTest(size=len(data)), self.assertRaises(preflight.Refusal):
                preflight.validate(data, ID, PROJECT, self.now)

    def test_never_started_identity_execution_resource_and_host_guards(self):
        changes = [
            lambda n: n.update(Id='b' * 64), lambda n: n.update(Name='/other-cluster-1'),
            lambda n: n['State'].update(Status='running'), lambda n: n['State'].update(StartedAt='2026-01-01T00:00:00Z'),
            lambda n: n.update(RestartCount=1), lambda n: n.update(RestartCount=False),
            lambda n: n.update(Created='2020-01-01T00:00:00Z'),
            lambda n: n['Config'].update(Hostname='operator-selected'),
            lambda n: n['Config'].update(WorkingDir='/tmp'),
            lambda n: n['Config']['Labels'].update({'com.docker.compose.project': 'other'}),
            lambda n: n['Config'].update(Image='rancher/k3s:latest'),
            lambda n: n['Config'].update(Cmd=['unreviewed startup']),
            lambda n: n['Config']['Env'].append('LD_PRELOAD=/unknown'),
            lambda n: n['HostConfig'].update(Memory=1024), lambda n: n['HostConfig'].update(NanoCpus=True),
            lambda n: n['HostConfig'].update(PidMode='host'), lambda n: n['HostConfig'].update(UTSMode='host'),
            lambda n: n['HostConfig'].update(IpcMode='host'), lambda n: n['HostConfig'].update(NetworkMode='host'),
            lambda n: n['HostConfig'].update(CapAdd=['SYS_ADMIN']),
            lambda n: n['HostConfig'].update(Devices=[{'PathOnHost': '/dev/unknown'}]),
            lambda n: n['HostConfig'].update(VolumesFrom=['other-container']),
            lambda n: n['HostConfig'].update(PortBindings={'6443/tcp': [{'HostPort': '6443'}]}),
            lambda n: n['NetworkSettings']['Networks'].update({'unexpected': {}}),
            lambda n: n['HostConfig']['Tmpfs'].update({'/var/run': ''}),
        ]
        for index, change in enumerate(changes):
            objects = copy.deepcopy(self.objects)
            change(objects[0])
            with self.subTest(case=index), self.assertRaises(preflight.Refusal):
                self.validate(objects)

    def test_structural_mounts_and_complete_volume_provenance_refuse_host_aliases(self):
        changes = [
            lambda xs: xs[0]['Mounts'][0].update(Type='bind', Source='/'),
            lambda xs: xs[0]['Mounts'][0].update(Destination='/var'),
            lambda xs: xs[0]['Mounts'][0].update(Destination='/var/run'),
            lambda xs: xs[0]['Mounts'][0].update(Name='extra-named-volume'),
            lambda xs: xs[0]['HostConfig'].update(Binds=['/var:/var']),
            lambda xs: xs[0]['Mounts'][0].update(RW=False),
            lambda xs: xs[1].update(Driver='untrusted'),
            lambda xs: xs[1].update(Options={'type': 'none', 'device': '/', 'o': 'bind'}),
            lambda xs: xs[1].update(Mountpoint='/host/root'),
            lambda xs: xs[1].update(CreatedAt='2020-01-01T00:00:00Z'),
            lambda xs: xs[1].update(Labels={'com.docker.compose.project': 'other'}),
            lambda xs: xs[-1].update(Name='missing-actual-volume'),
        ]
        for index, change in enumerate(changes):
            objects = copy.deepcopy(self.objects)
            change(objects)
            with self.subTest(case=index), self.assertRaises(preflight.Refusal):
                self.validate(objects)

    def test_only_native_privileged_label_disable_security_option_is_accepted(self):
        for value in (None, [], ['label=disable']):
            objects = copy.deepcopy(self.objects)
            objects[0]['HostConfig']['SecurityOpt'] = value
            self.validate(objects)
        for value in (['seccomp=unconfined'], ['apparmor=unconfined'], ['label=disable', 'seccomp=unconfined'],
                      ['label=disable', 'apparmor=unconfined'], ['label=disable', 'label=disable'], ['label=disabled']):
            objects = copy.deepcopy(self.objects)
            objects[0]['HostConfig']['SecurityOpt'] = value
            with self.subTest(value=value), self.assertRaises(preflight.Refusal):
                self.validate(objects)

    def test_pinned_volume_declaration_requires_tmpfs_and_structural_readonly_false(self):
        for read_only in ('omitted', False):
            objects = copy.deepcopy(self.objects)
            mount = {'Type': 'volume', 'Source': PROJECT + '_credentials', 'Target': '/fixture', 'VolumeOptions': {}}
            if read_only != 'omitted': mount['ReadOnly'] = read_only
            objects[0]['HostConfig'].update(Binds=None, Mounts=[mount])
            self.validate(objects)
        for read_only in (True, None, 'false'):
            objects = copy.deepcopy(self.objects)
            objects[0]['HostConfig']['Mounts'] = [{'Type': 'volume', 'Source': PROJECT + '_credentials',
                'Target': '/fixture', 'ReadOnly': read_only, 'VolumeOptions': {}}]
            with self.subTest(readOnly=read_only), self.assertRaises(preflight.Refusal):
                self.validate(objects)
        changes = [lambda n: n['Config']['Volumes'].update({'/var/run': {}}),
                   lambda n: n['Mounts'][0].update(Destination='/var/lib/rancher/k3s'),
                   lambda n: n['HostConfig']['Tmpfs'].pop('/var/lib/rancher/k3s')]
        for change in changes:
            objects = copy.deepcopy(self.objects)
            change(objects[0])
            with self.assertRaises(preflight.Refusal):
                self.validate(objects)

    def test_atomic_receipt_is_root_0600_single_link_and_cannot_resume(self):
        record = self.validate()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            digest = preflight.write_receipt(record, directory, self.now)
            receipt = directory / 'preflight.receipt'
            details = receipt.lstat()
            self.assertEqual((details.st_uid, details.st_gid, stat.S_IMODE(details.st_mode), details.st_nlink), (0, 0, 0o600, 1))
            self.assertEqual(len(digest), 64)
            self.assertEqual(receipt.read_text().splitlines(), [preflight.VERSION, ID, ID[:12], PROJECT,
                str(self.now), str(self.now + preflight.TTL), record['inspectSha256']])
            self.assertEqual(list(directory.iterdir()), [receipt])
            with self.assertRaises(preflight.Refusal):
                preflight.write_receipt(record, directory, self.now)
            receipt.rename(directory / 'preflight.consumed')
            with self.assertRaises(preflight.Refusal):
                preflight.write_receipt(record, directory, self.now)

    def test_validation_refusal_and_unsafe_credential_directories_write_nothing(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with self.assertRaises(preflight.Refusal):
                record = preflight.validate(b'[]', ID, PROJECT, self.now)
                preflight.write_receipt(record, directory, self.now)
            self.assertEqual(list(directory.iterdir()), [])
            directory.chmod(0o777)
            with self.assertRaises(preflight.Refusal):
                preflight.write_receipt(self.validate(), directory, self.now)
            self.assertEqual(list(directory.iterdir()), [])
            directory.chmod(0o700)
            linked = directory / 'linked'
            linked.symlink_to(directory, target_is_directory=True)
            with self.assertRaises(OSError):
                preflight.write_receipt(self.validate(), linked, self.now)
            self.assertEqual(list(directory.iterdir()), [linked])


class StartupTests(unittest.TestCase):
    def assert_mount_commands(self, source):
        self.assertEqual([line.strip() for line in source.splitlines() if ' -o ' in line], [
            '/bin/aux/mount -o bind "$target" "$target" || refuse',
            '/bin/aux/mount -o make-private "$target" || refuse',
            '/bin/aux/mount -o make-shared "$target" || refuse'])

    def prepare(self, directory):
        credentials = directory / 'credentials'
        credentials.mkdir(mode=0o700)
        variable = directory / 'node-var'
        variable.mkdir(mode=0o755)
        run = variable / 'run'
        run.mkdir(mode=0o755)
        target = run / 'netns'
        target.mkdir(mode=0o700)
        mountinfo = directory / 'mountinfo'
        mountinfo.write_text('1 0 0:1 / / rw master:98 - overlay overlay rw\n')
        log = directory / 'mutations'
        binary = directory / 'bin'
        binary.mkdir()
        mount = binary / 'mount'
        mount.write_text('''#!/usr/local/bin/python
import json,os,pathlib,sys
info=pathlib.Path(os.environ['GUARD_MOUNTINFO']); target=os.environ['GUARD_TARGET']
mask=os.umask(0); os.umask(mask)
with open(os.environ['GUARD_LOG']+'.umask','a') as stream: stream.write(format(mask,'03o')+'\\n')
with open(os.environ['GUARD_LOG'],'a') as stream: stream.write(json.dumps(sys.argv[1:])+'\\n')
option=sys.argv[2]
if option not in ('bind','make-private','make-shared'): raise SystemExit(42)
mode={'bind':'bind','make-private':'private','make-shared':'shared'}[option]
lines=info.read_text().splitlines(); root=lines[0]
expected=['-o',option,target]+([target] if mode=='bind' else [])
if sys.argv[1:]!=expected: raise SystemExit(42)
if mode=='private' and os.environ.get('GUARD_FAULT')=='root': root=root.replace('master:98','master:99')
flags={'bind':'master:98','private':'','shared':'shared:123'}[mode]
if os.environ.get('GUARD_FAULT')==mode: flags='shared:123 master:98' if mode=='shared' else 'master:98'
mount_root=target
if os.environ.get('GUARD_FAULT')==mode+'-all':
    mount_root='/'; flags='master:98 propagate_from:99'+(' shared:123' if mode=='private' else '')
record='2 1 0:1 '+mount_root+' '+target+' rw '+flags+' - overlay overlay rw\\n'
if os.environ.get('GUARD_FAULT')==mode+'-zero': record=''
if os.environ.get('GUARD_FAULT')==mode+'-multiple': record+=record
if os.environ.get('GUARD_FAULT')==mode+'-descendant': record+='3 2 0:1 / '+target+'/child rw - overlay overlay rw\\n'
info.write_text(root+'\\n'+record)
''')
        mount.chmod(0o600)
        source, commands = preflight.canonical_startup()
        script = commands[0].split('# BEGIN ORIGINAL STARTUP', 1)[0]
        self.assert_mount_commands(script)
        self.assertEqual(script.count('/bin/aux/mount'), 3)
        script = script.replace('/bin/aux/mount', 'mount_probe')
        replacements = {'/fixture': credentials, '/var/run/netns': target, '/var/run': run,
                        '/var': variable, '/proc/self/mountinfo': mountinfo}
        for index, path in enumerate(replacements):
            script = script.replace(path, '@PATH' + str(index) + '@')
        for index, path in enumerate(replacements):
            script = script.replace('@PATH' + str(index) + '@', str(replacements[path]))
        # /tmp remains noexec; functions invoke the trusted interpreter explicitly.
        script = ('hostname() { printf "%s\\n" "' + ID[:12] + '"; }\n'
                  'mount_probe() { /usr/local/bin/python "' + str(mount) + '" "$@"; }\n' + script)
        env = dict(os.environ, FIXTURE_PROJECT=PROJECT,
                   GUARD_MOUNTINFO=str(mountinfo), GUARD_TARGET=str(target), GUARD_LOG=str(log))
        now = int(time.time())
        record = preflight.validate(json.dumps(inspected(now)).encode(), ID, PROJECT, now)
        preflight.write_receipt(record, credentials, now)
        return credentials, variable, run, target, mountinfo, log, script, env

    def execute(self, script, env):
        return subprocess.run(['/bin/sh', '-c', script], env=env, capture_output=True, text=True, timeout=10)

    def test_valid_source_guard_consumes_once_and_mounts_only_fixed_target_in_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            credentials, variable, run, target, info, log, script, env = self.prepare(Path(temporary))
            result = self.execute(script, env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((credentials / 'preflight.receipt').exists())
            self.assertEqual((credentials / 'preflight.consumed').stat().st_nlink, 1)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual(calls, [['-o', 'bind', str(target), str(target)],
                                    ['-o', 'make-private', str(target)], ['-o', 'make-shared', str(target)]])
            count = log.read_text()
            self.assertNotEqual(self.execute(script, env).returncode, 0)
            self.assertEqual(log.read_text(), count)

    def test_bad_receipt_refuses_before_target_or_storage_mutations(self):
        for case in ('missing', 'mode', 'owner', 'hardlink', 'symlink', 'fifo', 'stale', 'project',
                     'hostname', 'recreated', 'extra', 'unterminated-extra', 'hex', 'version', 'consumed'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                credentials, variable, run, target, info, log, script, env = self.prepare(Path(temporary))
                receipt = credentials / 'preflight.receipt'
                lines = receipt.read_text().splitlines()
                if case == 'missing': receipt.unlink()
                elif case == 'mode': receipt.chmod(0o644)
                elif case == 'owner': os.chown(receipt, 65534, 65534)
                elif case == 'hardlink': os.link(receipt, credentials / 'second-link')
                elif case == 'symlink':
                    receipt.rename(credentials / 'actual'); receipt.symlink_to(credentials / 'actual')
                elif case == 'fifo': receipt.unlink(); os.mkfifo(receipt)
                elif case == 'consumed': (credentials / 'preflight.consumed').symlink_to('/absent')
                else:
                    if case == 'stale': lines[4:6] = [str(int(time.time()) - 300), str(int(time.time()) - 180)]
                    elif case == 'project': lines[3] = 'obs-lifecycle-stack-other'
                    elif case == 'hostname': lines[2] = 'b' * 12
                    elif case == 'recreated': lines[1:3] = ['b' * 64, 'b' * 12]
                    elif case == 'hex': lines[1] = lines[1][:-1] + ':'
                    elif case == 'version': lines[0] = 'older-version'
                    elif case == 'extra': lines.append('unexpected')
                    receipt.write_text('\n'.join(lines) + ('\nunexpected' if case == 'unterminated-extra' else '\n'))
                target.rmdir()
                result = self.execute(script, env)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(target.exists())
                self.assertFalse(log.exists())

    def test_unknown_mounts_links_children_or_shared_root_are_not_adopted(self):
        for case in ('root-shared', 'ancestor-link', 'ancestor-owner', 'target-link', 'child', 'mounted', 'mounted-child'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                credentials, variable, run, target, info, log, script, env = self.prepare(Path(temporary))
                if case == 'root-shared': info.write_text('1 0 0:1 / / rw shared:98 - overlay overlay rw\n')
                elif case == 'ancestor-link':
                    target.rmdir(); run.rmdir(); run.symlink_to(variable)
                elif case == 'ancestor-owner': os.chown(variable, 65534, 65534)
                elif case == 'target-link': target.rmdir(); target.symlink_to(run)
                elif case == 'child': (target / 'unknown').touch()
                else:
                    path = str(target) + ('/child' if case == 'mounted-child' else '')
                    info.write_text(info.read_text() + '2 1 0:1 / ' + path + ' rw - overlay overlay rw\n')
                self.assertNotEqual(self.execute(script, env).returncode, 0)
                self.assertFalse(log.exists())

    def test_private_shared_and_root_postconditions_refuse_inherited_propagation(self):
        for fault, expected_calls, expected_stage in [
                ('private', 2, 'private-post'), ('shared', 3, 'shared-post'),
                ('private-all', 2, 'private-post'), ('shared-all', 3, 'shared-post'),
                ('root', 2, 'private-root-unchanged')]:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                credentials, variable, run, target, info, log, script, env = self.prepare(Path(temporary))
                env['GUARD_FAULT'] = fault
                result = self.execute(script, env)
                self.assertNotEqual(result.returncode, 0)
                expected = 'Local node preflight refused stage=' + expected_stage + '\n'
                if fault in ('private', 'shared'):
                    expected += ('rootFieldMatchesExpected=true noMaster=false noPropagateFrom=true '
                                 'expectedSharedState=true exactOneTarget=true\n')
                elif fault in ('private-all', 'shared-all'):
                    expected += ('rootFieldMatchesExpected=false noMaster=false noPropagateFrom=false '
                                 'expectedSharedState=false exactOneTarget=true\n')
                self.assertEqual(result.stderr, expected)
                self.assertEqual(len(log.read_text().splitlines()), expected_calls)

    def test_record_refusal_reports_only_count_and_descendant_booleans(self):
        booleans = {
            'zero': 'zeroTargets=true multipleTargets=false noTargetDescendants=true exactOneTarget=false\n',
            'multiple': 'zeroTargets=false multipleTargets=true noTargetDescendants=true exactOneTarget=false\n',
            'descendant': 'zeroTargets=false multipleTargets=false noTargetDescendants=false exactOneTarget=true\n',
        }
        for mode, calls in [('private', 2), ('shared', 3)]:
            for fault, diagnostic in booleans.items():
                with self.subTest(mode=mode, fault=fault), tempfile.TemporaryDirectory() as temporary:
                    credentials, variable, run, target, info, log, script, env = self.prepare(Path(temporary))
                    env['GUARD_FAULT'] = mode + '-' + fault
                    result = self.execute(script, env)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stderr, 'Local node preflight refused stage=' + mode + '-record\n' + diagnostic)
                    self.assertEqual(len(log.read_text().splitlines()), calls)

    def test_propagation_with_two_target_operands_refuses_before_next_operation(self):
        for mode, calls in [('private', 2), ('shared', 3)]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                credentials, variable, run, target, info, log, script, env = self.prepare(Path(temporary))
                command = 'mount_probe -o make-' + mode + ' "$target"'
                self.assertEqual(script.count(command), 1)
                result = self.execute(script.replace(command, command + ' "$target"'), env)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stderr, 'Local node preflight refused stage=' + mode + '\n')
                self.assertEqual(len(log.read_text().splitlines()), calls)

    def test_exact_source_mount_contract_rejects_old_tokens_recursive_options_and_other_executables(self):
        source = preflight.canonical_startup()[1][0]
        self.assert_mount_commands(source)
        for original, replacement in [
                ('make-private', 'private'), ('make-shared', 'shared'),
                ('make-private', 'make-rprivate'), ('make-shared', 'make-rshared'), ('-o bind', '-o rbind'),
                ('/bin/aux/mount', 'mount'), ('/bin/aux/mount', '/bin/mount'),
                ('/bin/aux/mount', '/usr/bin/mount'),
                ('make-private "$target"', 'make-private "$target" "$target"'),
                ('make-shared "$target"', 'make-shared "$target" "$target"')]:
            with self.subTest(replacement=replacement), self.assertRaises(AssertionError):
                self.assert_mount_commands(source.replace(original, replacement))

    def test_original_startup_passes_all_flags_as_one_actual_shell_exec(self):
        expected = ['server', '--node-name=obs-lifecycle-stack',
                    '--disable=traefik,servicelb,local-storage,metrics-server', '--tls-san=cluster',
                    '--node-ip=10.245.239.2', '--advertise-address=10.245.239.2', '--flannel-iface=eth0',
                    '--write-kubeconfig=/fixture/kubeconfig', '--write-kubeconfig-mode=600']
        source = preflight.canonical_startup()[1][0].split('# BEGIN ORIGINAL STARTUP', 1)[1]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            recorder = directory / 'arguments.py'
            recorder.write_text('import json,sys; print(json.dumps(sys.argv[1:]))\n')
            script = source.replace('/var/lib/lifecycle-storage', str(directory / 'storage'))
            script = script.replace('exec k3s', 'exec /usr/local/bin/python "$ARG_RECORDER"')
            env = dict(os.environ, ARG_RECORDER=str(recorder))
            result = self.execute('set -eu\n' + script, env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), expected)
            # Real shell parsing must detect each lost continuation; exec hides later lines.
            self.assertEqual(script.count('\\\n'), 3)
            for index in range(3):
                pieces = script.split('\\\n')
                broken = '\\\n'.join(pieces[:index + 1]) + '\n' + '\\\n'.join(pieces[index + 1:])
                result = self.execute('set -eu\n' + broken, env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotEqual(json.loads(result.stdout), expected)

    def test_private_preparation_uses_077_and_original_exec_preserves_incoming_umask(self):
        for incoming in ('022', '027'):
            for missing_restore in (False, True):
                with self.subTest(incoming=incoming, missing_restore=missing_restore), tempfile.TemporaryDirectory() as temporary:
                    directory = Path(temporary)
                    credentials, variable, run, target, info, log, script, env = self.prepare(directory)
                    recorder = directory / 'umask.py'
                    recorder.write_text("import json,os; print(json.dumps({'umask':format(os.umask(0),'03o')}))\n")
                    original = preflight.canonical_startup()[1][0].split('# BEGIN ORIGINAL STARTUP', 1)[1]
                    original = original.replace('/var/lib/lifecycle-storage', str(directory / 'storage'))
                    original = original.replace('exec k3s', 'exec /usr/local/bin/python "$ARG_RECORDER"')
                    env['ARG_RECORDER'] = str(recorder)
                    restore = 'umask "$incoming_umask" || refuse'
                    self.assertEqual(script.count(restore), 1)
                    if missing_restore:
                        script = script.replace(restore, ':')
                    result = self.execute('umask ' + incoming + '\n' + script + '\n' + original, env)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(Path(str(log) + '.umask').read_text().splitlines(), ['077'] * 3)
                    actual = json.loads(result.stdout.splitlines()[-1])['umask']
                    if missing_restore:
                        self.assertNotEqual(actual, incoming)
                        self.assertEqual(actual, '077')
                    else:
                        self.assertEqual(actual, incoming)

    def test_versioned_source_has_receipt_before_every_original_mutation_and_no_recursive_mount(self):
        _, commands = preflight.canonical_startup()
        source = commands[0]
        self.assertLess(source.index('# END RECEIPT GUARD'), source.index('mkdir "$target"'))
        self.assertLess(source.index('# END RECEIPT GUARD'), source.index('mkdir -p /var/lib/lifecycle-storage'))
        self.assertLess(source.index('# END NETNS GUARD'), source.index('chmod 0777'))
        self.assert_mount_commands(source)
        self.assertIn('target=/var/run/netns', source)
        self.assertNotIn('eval ', source)
        self.assertNotIn('rshared', source)


if __name__ == '__main__':
    unittest.main()

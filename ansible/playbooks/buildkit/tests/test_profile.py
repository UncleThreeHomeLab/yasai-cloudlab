import hashlib
import json
from pathlib import Path
import re
import tempfile
import unittest

from playbooks.buildkit.tests import fixtures


class BuilderProfileTests(unittest.TestCase):
    def test_seccomp_retains_default_denial_and_only_required_namespace_extensions(self):
        raw = (fixtures.BASE / 'files/buildkit-seccomp.json').read_bytes()
        lock = json.loads((fixtures.BASE / 'files/profiles.lock.json').read_text())
        for name in ('seccomp', 'apparmor'):
            artifact = lock[name]
            self.assertEqual(hashlib.sha256((fixtures.BASE / 'files' / artifact['file']).read_bytes()).hexdigest(),
                             artifact['sha256'])
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         '81c24837e0bf9ea3c4ec909b5f988259f21b8f77073d3f0b0e55c79979e64336')
        profile = json.loads(raw)
        self.assertEqual(profile['defaultAction'], 'SCMP_ACT_ERRNO')
        self.assertEqual(profile['architectures'], ['SCMP_ARCH_X86_64'])
        self.assertEqual(set(profile['syscalls'][-1]['names']),
                         {'chroot', 'clone', 'mount', 'pivot_root', 'sethostname', 'setns', 'umount2', 'unshare'})
        allowed = {name for row in profile['syscalls'] if row['action'] == 'SCMP_ACT_ALLOW' for name in row['names']}
        self.assertFalse(allowed & {'bpf', 'kexec_load', 'reboot', 'perf_event_open', 'init_module', 'delete_module'})
        self.assertTrue(any(row['names'] == ['clone3'] and row['errnoRet'] == 38 for row in profile['syscalls']))

    def test_only_builder_has_the_exact_user_namespace_exceptions(self):
        configuration = fixtures.values()
        self.assertEqual((configuration['minRunners'], configuration['maxRunners']), (0, 1))
        pod = configuration['template']['spec']
        self.assertIs(pod['hostUsers'], False)
        self.assertIs(pod['automountServiceAccountToken'], False)
        self.assertFalse(any(pod.get(field) for field in ('hostNetwork', 'hostPID', 'hostIPC', 'shareProcessNamespace')))
        self.assertEqual(pod['securityContext']['runAsUser'], 1000)
        for container in pod['containers']:
            self.assertRegex(container['image'], r'@sha256:[a-f0-9]{64}$')
            profile = container['securityContext']
            self.assertFalse(profile.get('privileged'))
            self.assertIs(profile['readOnlyRootFilesystem'], True)
            self.assertEqual(profile['capabilities']['drop'], ['ALL'])
            if container['name'] == 'builder':
                self.assertEqual(profile['capabilities']['add'], ['SETUID', 'SETGID'])
                self.assertIs(profile['allowPrivilegeEscalation'], True)
                self.assertEqual(profile['procMount'], 'Unmasked')
                self.assertEqual(profile['seccompProfile'], {'type': 'Localhost', 'localhostProfile': 'cloudlab/buildkit.json'})
                self.assertEqual(profile['appArmorProfile'], {'type': 'Localhost', 'localhostProfile': 'cloudlab-buildkit'})
                self.assertIn({'name': 'TMPDIR', 'value': '/tmp'}, container['env'])
                self.assertNotIn('--oci-worker-no-process-sandbox', ' '.join(container['args']))
                self.assertEqual(container['resources']['limits'], {'cpu': '2', 'memory': '4Gi', 'ephemeral-storage': '24Gi'})
            else:
                self.assertIs(profile['allowPrivilegeEscalation'], False)
                self.assertNotIn('add', profile['capabilities'])
        self.assertFalse(any('hostPath' in volume or 'persistentVolumeClaim' in volume or 'secret' in volume for volume in pod['volumes']))
        self.assertEqual(sum(int(row['emptyDir']['sizeLimit'].removesuffix('Gi')) for row in pod['volumes'] if 'emptyDir' in row), 32)

    def test_native_templates_use_the_canonical_profile_and_bound_all_fixture_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            rendered = fixtures.render(Path(temporary))
        namespace, resources, job = (rendered[name] for name in ('namespace', 'resources', 'job'))
        self.assertEqual(namespace['metadata']['labels']['pod-security.kubernetes.io/enforce'], 'baseline')
        self.assertEqual(job['metadata']['namespace'], namespace['metadata']['name'])
        self.assertEqual(job['spec']['activeDeadlineSeconds'], 600)
        self.assertEqual(job['spec']['backoffLimit'], 0)
        pod = job['spec']['template']['spec']
        self.assertEqual(pod['nodeName'], 'node-a')
        self.assertEqual(len(pod['containers']), 1)
        expected = next(row for row in fixtures.values()['template']['spec']['containers'] if row['name'] == 'builder')
        self.assertEqual(pod['containers'][0]['securityContext'], expected['securityContext'])
        self.assertEqual(pod['containers'][0]['args'], expected['command'] + expected['args'])
        quota, ids, script = resources['items']
        self.assertEqual(quota['spec']['hard']['pods'], '1')
        self.assertEqual(quota['spec']['hard']['count/jobs.batch'], '1')
        self.assertEqual(quota['spec']['hard']['secrets'], '0')
        self.assertEqual(quota['spec']['hard']['persistentvolumeclaims'], '0')
        self.assertEqual(ids['metadata']['name'], 'cloudlab-buildkit-ids')
        self.assertEqual(ids['data']['subuid'], 'user:0:1000\nuser:1001:64535\n')
        self.assertEqual(ids['data']['subuid'], ids['data']['subgid'])
        self.assertTrue(script['immutable'])
        self.assertIn('CLOUDLAB_ROOTLESS_BUILD_OK', script['data']['build-proof.sh'])
        self.assertNotIn('--oci-worker-no-process-sandbox', script['data']['build-proof.sh'])
        for image in re.findall(r'^FROM (.+)$', script['data']['build-proof.sh'], re.M):
            self.assertRegex(image, r'@sha256:[a-f0-9]{64}$')

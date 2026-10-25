"""A chart update changes the archive, artifact lock, Helm lock and image values."""
import io
import base64
import json
from pathlib import Path
import tarfile
import shutil
import tempfile
import unittest
from unittest.mock import patch

import yaml

from playbooks.dependencies.files import charts
from playbooks.dependencies.files.security import digest
from playbooks.dependencies.files.workspace import changes, files
from playbooks.dependencies.tests.fixtures import MaintenanceAPI, tailscale_release


def chart(version, app_version, *, malicious=False):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as archive:
        raw = yaml.safe_dump({'apiVersion': 'v2', 'name': 'argo-cd', 'version': version,
                              'appVersion': app_version}).encode()
        item = tarfile.TarInfo('argo-cd/Chart.yaml')
        item.size = len(raw)
        archive.addfile(item, io.BytesIO(raw))
        if malicious:
            raw = b'apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata: {name: injected}\nrules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]\n'
            item = tarfile.TarInfo('argo-cd/templates/injected.yaml')
            item.size = len(raw)
            archive.addfile(item, io.BytesIO(raw))
    return output.getvalue()


class ChartTests(unittest.TestCase):
    def test_tailscale_index_timestamp_and_hash_survive_final_compatibility(self):
        from playbooks.dependencies.files import compatibility, control, workspace
        from playbooks.dependencies.files.gate import Gate, branch_prefix
        from playbooks.dependencies.files.check import source
        prefix = 'platform/connectivity/tailscale-operator/'
        old, new = tailscale_release('1.102.3'), tailscale_release('1.102.4')
        old_url = 'https://pkgs.tailscale.com/helmcharts/tailscale-operator-1.102.3-1789000000-' + digest(old) + '.tgz'
        new_url = 'https://pkgs.tailscale.com/helmcharts/tailscale-operator-1.102.4-1789680537-' + digest(new) + '.tgz'
        lock = {'version': '1.102.3', 'archive': 'charts/tailscale-operator-1.102.3.tgz',
                'upstream_url': old_url, 'upstream_sha256': digest(old),
                'sha256': digest(charts.patch('connectivity/tailscale-operator', old))}
        dependency = {'name': 'tailscale-operator', 'version': '1.102.3', 'repository': 'https://pkgs.tailscale.com/helmcharts'}
        base = {prefix + 'artifact.lock.json': json.dumps(lock).encode(), prefix + 'upstream.tgz': old,
                prefix + lock['archive']: charts.patch('connectivity/tailscale-operator', old),
                prefix + 'Chart.yaml': yaml.safe_dump({'apiVersion': 'v2', 'name': 'fixture', 'version': '0.1.0', 'dependencies': [dependency]}).encode(),
                prefix + 'Chart.lock': yaml.safe_dump({'dependencies': [dependency], 'digest': charts.dependencies_hash([dependency], [dependency])}).encode(),
                prefix + 'values.yaml': b'{}\n',
                'platform/connectivity/access/images.lock.json': json.dumps({'images': {
                    'ingress': 'tailscale/tailscale:v1.102.4@sha256:' + 'a' * 64}}).encode()}
        head = dict(base)
        head[prefix + 'Chart.yaml'] = head[prefix + 'Chart.yaml'].replace(b'1.102.3', b'1.102.4')
        row = {'version': '1.102.4', 'urls': [new_url], 'digest': digest(new)}
        def fetch(url, **arguments):
            return yaml.safe_dump({'entries': {'tailscale-operator': [row]}}).encode() if url.endswith('/index.yaml') else new
        with tempfile.TemporaryDirectory() as temporary:
            root, store = Path(temporary) / 'candidate', Path(temporary) / 'control'
            store.mkdir()
            api = MaintenanceAPI(base, head)
            gate = Gate(api, {'repository': 'example/platform', 'repositoryId': 1, 'requester': 'release[bot]',
                             'base': 'main', 'branchPrefix': branch_prefix('main')}, store)
            with patch.object(control, 'CANDIDATE', root), patch.object(control, 'CONTROL', store), \
                    patch.object(control, 'snapshot', side_effect=api.snapshot), patch.object(workspace, 'snapshot', side_effect=api.snapshot):
                control.export_pr(gate, 7, ['chart:connectivity/tailscale-operator'])
                with patch.object(charts.images, 'update') as coupled_repair:
                    charts.update(root, 'connectivity/tailscale-operator', '1.102.4', fetch=fetch)
                    coupled_repair.assert_called_once_with(root, 'access', {'selector': 'ingress', 'version': 'v1.102.4'})
                plan = control.load('check-plan.json')
                source(root, plan)
                compatibility.verify(root, plan)
                charts.provenance(root, plan, fetch=fetch)
                target = root / prefix / 'artifact.lock.json'
                repaired = target.read_bytes()
                for url in (new_url.replace('pkgs.tailscale.com', 'github.com'), new_url.replace('/helmcharts/', '/stable/'),
                            new_url + '?query=value', new_url.replace('tailscale-operator-', 'another-chart-', 1)):
                    metadata = json.loads(repaired)
                    metadata['upstream_url'] = url
                    target.write_text(json.dumps(metadata))
                    with self.subTest(url=url), self.assertRaises(ValueError):
                        compatibility.verify(root, plan)
                target.write_bytes(repaired)
                metadata = json.loads(repaired)
                metadata['upstream_url'] = new_url.replace('1789680537', '1789000001')
                target.write_text(json.dumps(metadata))
                compatibility.verify(root, plan)
                with self.assertRaises(ValueError):
                    charts.provenance(root, plan, fetch=fetch)
                target.write_bytes(repaired)
                row['digest'] = 'f' * 64
                with self.assertRaises(ValueError):
                    charts.provenance(root, plan, fetch=fetch)

    def test_current_registered_archives_authenticate_without_network(self):
        from playbooks.dependencies.files.inventory import ROOT
        sources = list((ROOT / 'platform').rglob('artifact.lock.json'))
        plan = {'baseFiles': {path.relative_to(ROOT).as_posix(): base64.b64encode(path.read_bytes()).decode()
                              for path in sources}}
        charts.provenance(ROOT, plan, fetch=lambda *args, **kwargs: self.fail('Unchanged approved bytes require no download'))

    def test_raw_archive_change_cannot_use_unchanged_pin_shortcut(self):
        from playbooks.dependencies.files.inventory import ROOT
        relative = 'platform/connectivity/istio/base/artifact.lock.json'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / Path(relative).parent
            shutil.copytree(ROOT / Path(relative).parent, directory)
            plan = {'baseFiles': {relative: base64.b64encode((ROOT / relative).read_bytes()).decode()}}
            charts.provenance(root, plan, fetch=lambda *args, **kwargs: self.fail('Unexpected download'))
            (directory / 'upstream.tgz').write_bytes(b'changed raw companion')
            with self.assertRaisesRegex(ValueError, 'Raw chart bytes'):
                charts.provenance(root, plan, fetch=lambda *args, **kwargs: self.fail('Unexpected download'))

    def test_helm_hash_matches_existing_native_locks(self):
        from playbooks.dependencies.files.inventory import ROOT
        for name in ('platform/delivery/argocd', 'platform/secrets/external-secrets', 'platform/storage/longhorn'):
            directory = ROOT / name
            wrapper = yaml.safe_load((directory / 'Chart.yaml').read_text())
            lock = yaml.safe_load((directory / 'Chart.lock').read_text())
            self.assertEqual(charts.dependencies_hash(wrapper['dependencies'], lock['dependencies']), lock['digest'])

    def test_complete_chart_fixture_update_and_narrow_archive_rename(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            owner = root / 'platform/delivery/argocd'
            (owner / 'charts').mkdir(parents=True)
            old, updated = chart('10.9.5', 'v3.5.2'), chart('10.9.6', 'v3.5.3')
            (owner / 'charts/argo-cd-10.9.5.tgz').write_bytes(old)
            url = 'https://github.com/argoproj/argo-helm/releases/download/argo-cd-10.9.5/argo-cd-10.9.5.tgz'
            lock = {'chart': {'version': '10.9.5', 'app_version': 'v3.5.2', 'url': url,
                              'archive': 'charts/argo-cd-10.9.5.tgz', 'sha256': digest(old)},
                    'images': {'quay.io/argoproj/argocd:v3.5.2': 'sha256:' + 'a' * 64}}
            (owner / 'artifact.lock.json').write_text(json.dumps(lock))
            dependency = {'name': 'argo-cd', 'version': '10.9.5', 'repository': 'https://argoproj.github.io/argo-helm'}
            (owner / 'Chart.yaml').write_text(yaml.safe_dump({'apiVersion': 'v2', 'name': 'fixture', 'version': '0.1.0',
                                                           'dependencies': [dependency]}))
            (owner / 'Chart.lock').write_text(yaml.safe_dump({'dependencies': [dependency],
                'digest': charts.dependencies_hash([dependency], [dependency]), 'generated': '2000-01-01T00:00:00Z'}))
            (owner / 'values.yaml').write_text(yaml.safe_dump({'image': 'quay.io/argoproj/argocd:v3.5.2@sha256:' + 'a' * 64}))
            baseline = files(root)

            def fetch(url, *, prefix):
                self.assertIn('10.9.6', url)
                self.assertTrue(url.startswith(prefix))
                return updated

            with patch.object(charts.images, 'image_digest', side_effect=lambda image: image + '@sha256:' + 'b' * 64):
                result = charts.update(root, 'delivery/argocd', '10.9.6', fetch=fetch)
            current = json.loads((owner / 'artifact.lock.json').read_text())
            self.assertEqual(current['chart']['sha256'], digest(updated))
            self.assertEqual(current['chart']['version'], '10.9.6')
            self.assertIn('10.9.6', current['chart']['url'])
            self.assertEqual(current['chart']['archive'], 'charts/argo-cd-10.9.6.tgz')
            self.assertFalse((owner / 'charts/argo-cd-10.9.5.tgz').exists())
            self.assertIn('v3.5.3@sha256:' + 'b' * 64, (owner / 'values.yaml').read_text())
            native = yaml.safe_load((owner / 'Chart.lock').read_text())
            wrapper = yaml.safe_load((owner / 'Chart.yaml').read_text())
            self.assertEqual(native['digest'], charts.dependencies_hash(wrapper['dependencies'], native['dependencies']))
            allowed = set(baseline) | set(files(root))
            patch_files = changes(root, baseline, allowed)
            self.assertIsNone(patch_files['platform/delivery/argocd/charts/argo-cd-10.9.5.tgz'])
            self.assertEqual(patch_files['platform/delivery/argocd/charts/argo-cd-10.9.6.tgz'], updated)
            self.assertEqual(result['status'], 'pending-verification')

    def test_existing_patch_rejects_an_unexpected_upstream_layout(self):
        with self.assertRaises(ValueError):
            charts.patch('certificates/cert-manager', chart('1.21.3', 'v1.21.3'))

    def test_draft_export_repair_publish_final_export_and_head_receipt(self):
        from playbooks.dependencies.files import control, workspace
        from playbooks.dependencies.files.gate import Gate, branch_prefix
        from playbooks.dependencies.files.inventory import fingerprint, selected
        from playbooks.dependencies.files.check import source
        with tempfile.TemporaryDirectory() as directory:
            root, store = Path(directory) / 'candidate', Path(directory) / 'control'
            store.mkdir()
            prefix = 'platform/delivery/argocd/'
            old = chart('10.9.5', 'v3.5.2')
            dependency = {'name': 'argo-cd', 'version': '10.9.5', 'repository': 'https://argoproj.github.io/argo-helm'}
            base = {prefix + 'charts/argo-cd-10.9.5.tgz': old,
                    prefix + 'Chart.yaml': yaml.safe_dump({'apiVersion': 'v2', 'name': 'fixture', 'version': '0.1.0',
                                                          'dependencies': [dependency]}).encode(),
                    prefix + 'Chart.lock': yaml.safe_dump({'dependencies': [dependency],
                        'digest': charts.dependencies_hash([dependency], [dependency]), 'generated': '2000-01-01T00:00:00Z'}).encode(),
                    prefix + 'artifact.lock.json': json.dumps({'chart': {'version': '10.9.5',
                        'app_version': 'v3.5.2', 'url': 'https://github.com/argoproj/argo-helm/releases/download/argo-cd-10.9.5/argo-cd-10.9.5.tgz',
                        'archive': 'charts/argo-cd-10.9.5.tgz', 'sha256': digest(old)},
                        'images': {'quay.io/argoproj/argocd:v3.5.2': 'sha256:' + 'a' * 64}}).encode(),
                    prefix + 'values.yaml': ('image: quay.io/argoproj/argocd:v3.5.2@sha256:' + 'a' * 64 + '\n').encode()}
            head = dict(base)
            head[prefix + 'Chart.yaml'] = head[prefix + 'Chart.yaml'].replace(b'10.9.5', b'10.9.6')
            api = MaintenanceAPI(base, head)
            scope = {'repository': 'example/platform', 'repositoryId': 1, 'requester': 'release[bot]',
                     'base': 'main', 'branchPrefix': branch_prefix('main')}
            gate = Gate(api, scope, store)
            with patch.object(control, 'CANDIDATE', root), patch.object(control, 'CONTROL', store), \
                    patch.object(control, 'snapshot', side_effect=api.snapshot), \
                    patch.object(workspace, 'snapshot', side_effect=api.snapshot):
                control.export_pr(gate, 7, ['chart:delivery/argocd'])
                with patch.object(charts.images, 'image_digest', side_effect=lambda image: image + '@sha256:' + 'b' * 64):
                    charts.update(root, 'delivery/argocd', '10.9.6', fetch=lambda *args, **kwargs: chart('10.9.6', 'v3.5.3'))
                source(root, control.load('check-plan.json'))
                plan = control.load('check-plan.json')
                official = chart('10.9.6', 'v3.5.3')
                charts.provenance(root, plan, fetch=lambda *args, **kwargs: official)
                artifact = root / prefix / 'artifact.lock.json'
                approved = artifact.read_bytes()
                poisoned = chart('10.9.6', 'v3.5.3', malicious=True)
                archive = root / prefix / 'charts/argo-cd-10.9.6.tgz'
                clean = archive.read_bytes()
                archive.write_bytes(poisoned)
                metadata = json.loads(approved)
                metadata['chart']['sha256'] = digest(poisoned)
                artifact.write_text(json.dumps(metadata))
                source(root, plan)
                with self.assertRaisesRegex(ValueError, 'official deterministic'):
                    charts.provenance(root, plan, fetch=lambda *args, **kwargs: official)
                archive.write_bytes(clean)
                metadata['chart']['sha256'] = digest(clean)
                metadata['chart']['url'] = metadata['chart']['url'].replace('/argo-helm/', '/untrusted/')
                artifact.write_text(json.dumps(metadata))
                with self.assertRaisesRegex(ValueError, 'approved release path'):
                    charts.provenance(root, plan, fetch=lambda *args, **kwargs: official)
                artifact.write_bytes(approved)
                owners = selected(['chart:delivery/argocd'])
                before = workspace.tree(root)
                pins = fingerprint(root, owners)
                permitted = control.allowed(owners, set(base) | set(files(root)))
                patch_files = changes(root, control.load('baseline.json'), permitted)
                gate.publish(7, api.head, api.base, patch_files, permitted,
                             modes={path: '100644' for path in head})
                final_head = api.row['head']['sha']
                self.assertNotEqual(final_head, api.head)
                control.export_pr(gate, 7, ['chart:delivery/argocd'])
                self.assertEqual(changes(root, control.load('baseline.json'), permitted), {})
                self.assertEqual(source(root, control.load('check-plan.json')), before)
                charts.provenance(root, control.load('check-plan.json'), fetch=lambda *args, **kwargs: official)
                self.assertEqual(fingerprint(root, owners), pins)
                expected = {'candidateTree': before, 'pinset': pins, 'helpers': 'a' * 64,
                            'toolchain': ['fixture/image:1@sha256:' + 'a' * 64], 'checks': {'fixture-check': 'PASS'}}
                gate.stamp(7, {'head': final_head, 'base': api.base, **expected})
                self.assertEqual(gate.ready(7, expected)['head'], final_head)
                self.assertNotIn(prefix + 'charts/argo-cd-10.9.5.tgz', api.snapshot('example/platform', final_head))

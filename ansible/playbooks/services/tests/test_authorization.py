"""Native application ports, selected-source evidence and withdrawal remain exact."""
import copy
from contextlib import contextmanager
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import traceback
import unittest
from unittest.mock import patch

import yaml

from playbooks.services.files import gitops, inputs, owner, package, payload, transport, verify
from playbooks.services.tests.fixtures import approval, definition, owner_api, owner_files


def policies(value=None, approved=None, *, root=None, publication='ready'):
    rows = gitops.resources(value or definition(), approved or approval(),
        'https://github.com/example/platform.git', 'a' * 40, chart_root=root, publication=publication)
    return {row['metadata']['name']: row for row in rows if row['kind'] == 'AuthorizationPolicy'}


def permits(policy, principal, port):
    for rule in policy['spec'].get('rules', []):
        if not any(principal in source.get('source', {}).get('principals', []) for source in rule.get('from', [])): continue
        for target in rule.get('to', [{}]):
            operation = target.get('operation', {})
            if (('ports' not in operation or str(port) in operation['ports']) and
                    str(port) not in operation.get('notPorts', [])):
                return True
    return False


class AuthorizationTests(unittest.TestCase):
    def test_local_validation_context_never_rereads_checkout_owner_settings(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            local = base / 'docs/local/catalog.yaml'
            local.parent.mkdir(parents=True)
            value = {'catalog': [], 'dataApprovals': {}}
            local.write_text(yaml.safe_dump(value))
            public = {'repository': 'https://github.com/example/platform.git', 'services': {'revision': 'a' * 40}}
            with patch.object(inputs, 'ROOT', base), patch.object(inputs, 'dotenv_values',
                    return_value={'SERVICE_CATALOG_FILE': 'docs/local/catalog.yaml'}), patch.object(owner, 'chart') as fetch:
                self.assertEqual(inputs.catalog(public=public, chart_root=Path('/selected')), value)
                fetch.assert_not_called()

    def test_malformed_native_projection_never_exposes_rendered_private_content(self):
        public = {'repository': 'https://github.com/example/platform.git',
            'services': {'revision': 'a' * 40}, 'observability': {'enabled': False}}
        with patch.object(gitops, '_render', return_value='private-projection-sentinel: [\n'):
            with self.assertRaises(ValueError) as error:
                gitops.authorization_policies({'catalog': [], 'dataApprovals': {}}, public, Path('/selected'))
        self.assertNotIn('private-projection-sentinel', ''.join(traceback.format_exception(error.exception)))

    def test_ordinary_ports_and_each_gateway_class_are_positive_and_retire_in_place(self):
        value = definition()
        value['ports'].append({'name': 'private', 'port': 8443})
        value['exposure'] = {'class': 'public', 'hostname': 'public.example.invalid', 'access': 'public', 'port': 8080, 'path': '/'}
        value['additionalExposures'] = [dict(value['exposure'], **{'class': 'private', 'port': 8443,
            'hostname': 'private.internal.example.invalid', 'access': 'tailnet'})]
        selected = policies(value)['platform-workloads']
        callers = {'cluster.local/ns/cloudlab-app-synthetic/sa/synthetic': {8080, 8443},
            'cluster.local/ns/cloudlab-gateway-public/sa/cloudlab-istio': {8080},
            'cluster.local/ns/cloudlab-gateway-private/sa/cloudlab-istio': {8443},
            'cluster.local/ns/cloudlab-app-synthetic/sa/other': set()}
        for caller, allowed in callers.items():
            for port in (8080, 8443, 8081, 15008):
                self.assertEqual(permits(selected, caller, port), port in allowed)
        retired = policies(value, publication='retired')['platform-workloads']
        self.assertEqual(retired['metadata'], selected['metadata'])
        self.assertEqual(retired['spec']['rules'], [])

    def test_metrics_are_excluded_only_when_the_signal_is_enabled(self):
        from playbooks.observability.tests.fixtures import monitored_service_inputs
        value = monitored_service_inputs()['catalog'][0]['definition']
        selected = policies(value)['platform-workloads']
        app = 'cluster.local/ns/cloudlab-app-synthetic/sa/synthetic'
        prometheus = 'cluster.local/ns/cloudlab-observability/sa/cloudlab-prometheus'
        self.assertFalse(permits(selected, app, 9191))
        self.assertFalse(permits(selected, app, 8081))
        self.assertTrue(permits(selected, prometheus, 9191))
        self.assertFalse(permits(selected, prometheus, 8080))
        for logs in (False, True):
            with self.subTest(logs=logs):
                plain = definition()
                plain['ports'][0]['name'] = 'http-metrics'
                for probe in plain['health'].values(): probe['port'] = 'http-metrics'
                if logs:
                    plain['monitoring'] = copy.deepcopy(value['monitoring'])
                    plain['monitoring']['metrics'] = {'enabled': False}
                    plain['monitoring']['logs'] = {'enabled': True, 'profile': 'cloudlab-http-json-v1'}
                self.assertTrue(permits(policies(plain)['platform-workloads'], app, 8080))

    def notes(self):
        from playbooks.services.files.examples import definitions
        entry = definitions('example.invalid', 'https://github.com/example/platform.git', 'a' * 40,
                            'notes', 'notes')['catalog'][0]
        return entry

    def test_notes_policy_matches_actual_child_names_labels_and_ports(self):
        entry = self.notes()
        native = gitops.resources(entry['definition'], entry['approval'],
            'https://github.com/example/platform.git', 'a' * 40)
        source = next(row for row in native if row['kind'] == 'ApplicationSet')['spec']['template']['spec']['source']
        child = subprocess.run(['helm', 'template', 'notes', str(package.ROOT / 'apps/notes'), '-f', '-'],
            input=json.dumps(source['helm']['valuesObject']), capture_output=True, text=True, check=True, timeout=90)
        workloads = {row['metadata']['name']: row for row in yaml.safe_load_all(child.stdout) if row and row['kind'] == 'Deployment'}
        selected = {row['metadata']['name']: row for row in native if row['kind'] == 'AuthorizationPolicy'}
        self.assertEqual(selected['platform-workloads']['spec']['rules'], [])
        for component in ('web', 'api'):
            row = selected['platform-notes-' + component]
            name = row['spec']['selector']['matchLabels']['app.kubernetes.io/name']
            pod = workloads[name]['spec']['template']
            self.assertTrue(all(pod['metadata']['labels'][key] == expected for key, expected in row['spec']['selector']['matchLabels'].items()))
            self.assertEqual(pod['spec']['serviceAccountName'], name)
            ports = {str(port['containerPort']) for port in pod['spec']['containers'][0]['ports']}
            self.assertEqual(set(row['spec']['rules'][0]['to'][0]['operation']['ports']), ports)
        self.assertEqual((package.ROOT / 'platform/delivery/services/notes-workloads.yaml').read_bytes(), package.notes_workloads())

    def test_notes_probe_uses_web_even_when_api_identity_is_projected_first(self):
        entry = self.notes()
        native = list(policies(entry['definition'], entry['approval']).values())
        expected = [{'apiVersion': row['apiVersion'], 'kind': row['kind'],
            'metadata': {key: row['metadata'][key] for key in ('name', 'namespace')},
            'spec': copy.deepcopy(row['spec'])} for row in native]
        first = next(rule['from'][0]['source']['principals'][0] for row in expected for rule in row['spec']['rules'])
        self.assertTrue(first.endswith('/sa/notes-api'))
        def observed():
            rows = copy.deepcopy(expected)
            for row in rows:
                row['metadata']['annotations'] = {'argocd.argoproj.io/tracking-id':
                    'cloudlab-services:security.istio.io/AuthorizationPolicy:' + row['metadata']['namespace'] + '/' + row['metadata']['name']}
            return {'items': rows}
        with patch.object(transport, 'get', side_effect=lambda *args, **kwargs: observed()):
            self.assertEqual(transport.policy(entry, expected), 'notes-web')
            for row in expected:
                for rule in row['spec']['rules']:
                    for origin in rule['from']:
                        source = origin['source']
                        source['principals'] = [name for name in source['principals'] if not name.endswith('/sa/notes-web')]
            with self.assertRaisesRegex(RuntimeError, 'scoped web identity'):
                transport.policy(entry, expected)

    def test_notes_asset_is_complete_and_component_ports_never_form_a_union(self):
        entry = self.notes()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'chart'
            shutil.copytree(package.ROOT / 'platform/delivery/services', root)
            asset = root / 'notes-workloads.yaml'
            original = yaml.safe_load(asset.read_text())
            changed = copy.deepcopy(original)
            changed['api']['ports'] = [8081]
            asset.write_text(yaml.safe_dump(changed))
            with self.assertRaises(ValueError): policies(entry['definition'], entry['approval'], root=root)
            value = copy.deepcopy(entry['definition'])
            value['exposure'], value['additionalExposures'] = {'class': 'none'}, []
            value['oidc'] = {'enabled': False}
            selected = policies(value, entry['approval'], root=root)
            self.assertEqual(selected['platform-notes-api']['spec']['rules'][0]['to'], [{'operation': {'ports': ['8081']}}])
            self.assertEqual(selected['platform-notes-web']['spec']['rules'][0]['to'], [{'operation': {'ports': ['8080']}}])
            retired = policies(value, entry['approval'], root=root, publication='retired')
            self.assertTrue(all(row['spec']['rules'] == [] for row in retired.values()))
            for bad in ({}, {'web': original['web']}, dict(original, api={'name': 'notes-api', 'ports': ['*']})):
                asset.write_text(yaml.safe_dump(bad))
                with self.subTest(bad=bad), self.assertRaises(ValueError): policies(value, entry['approval'], root=root)
            asset.unlink()
            with self.assertRaises(ValueError): policies(value, entry['approval'], root=root)

    def test_payload_reuses_one_exact_selected_snapshot_for_old_and_current_policies(self):
        for legacy in (False, True):
            with self.subTest(legacy=legacy), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                public = {'repository': 'https://github.com/example/platform.git',
                    'services': {'revision': 'a' * 40, 'catalogPath': 'services/catalog-selected.yaml'}, 'observability': {'enabled': False}}
                path = base / 'gitops/roots/public/values.yaml'
                path.parent.mkdir(parents=True)
                path.write_text(yaml.safe_dump(public))
                files = owner_files()
                if legacy:
                    files.pop('templates/authorization.yaml')
                    files['templates/legacy.yaml'] = b'''{{ range .Values.catalog }}
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata: {name: platform-workloads, namespace: {{ .approval.namespace }}}
spec:
  selector: {matchLabels: {cloudlab.io/owner: {{ .definition.owner }}}}
  action: ALLOW
  rules:
    - from:
        - source: {principals: ['cluster.local/ns/{{ .approval.namespace }}/sa/{{ .definition.name }}']}
{{ end }}
'''
                fetch, read_file, _ = owner_api(files)
                real_chart = owner.chart
                def selected(settings): return real_chart(settings, fetch=fetch, read_file=read_file)
                private = {'catalog': [{'definition': definition(), 'approval': approval(), 'publication': 'ready'}], 'dataApprovals': {}}
                environment = {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git', 'OP_SERVICE_ACCOUNT_TOKEN': 'synthetic'}
                with patch.object(payload, 'ROOT', base), patch.object(payload, 'committed_payload', return_value={'repository': public['repository']}), \
                        patch.object(payload, 'dotenv_values', return_value=environment), patch.object(inputs, 'dotenv_values', return_value=environment), \
                        patch.object(owner, 'chart', side_effect=selected) as snapshot, \
                        patch('playbooks.services.files.source.read', return_value=(private, 'b' * 40)) as private_read:
                    result = payload.payload()
                snapshot.assert_called_once_with(public)
                self.assertEqual(fetch.call_count, 2)
                private_read.assert_called_once_with(environment, include_revision=True, public=public)
                self.assertNotIn('authorization', result['values'])
                projected = result['authorization']['cloudlab-app-synthetic'][0]
                rule = projected['spec']['rules'][0]
                self.assertEqual('to' in rule, not legacy)
                actual = copy.deepcopy(projected)
                actual['metadata']['annotations'] = {'argocd.argoproj.io/tracking-id':
                    'cloudlab-services:security.istio.io/AuthorizationPolicy:cloudlab-app-synthetic/platform-workloads'}
                with patch.object(transport, 'get', return_value={'items': [actual]}):
                    self.assertEqual(transport.policy(private['catalog'][0], [projected]), 'synthetic')
                    actual['spec']['rules'].append({'from': [{'source': {'principals': ['*']}}]})
                    with self.assertRaises(RuntimeError): transport.policy(private['catalog'][0], [projected])

    def test_missing_projection_stops_before_any_service_or_pod_operation(self):
        entry = {'definition': definition(), 'approval': approval(), 'publication': 'ready'}
        with patch('playbooks.services.files.catalog.converged', return_value=True), \
                patch.object(verify, 'inspect') as inspect, patch.object(verify, 'kube') as kube:
            with self.assertRaisesRegex(RuntimeError, 'authorization evidence'):
                verify.run({'values': {'catalog': [entry]}})
            inspect.assert_not_called()
            kube.assert_not_called()

    def test_selected_source_failure_or_public_change_never_returns_evidence(self):
        for unavailable in (False, True):
            with self.subTest(unavailable=unavailable), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                public = {'repository': 'https://github.com/example/platform.git',
                    'services': {'revision': 'a' * 40}, 'observability': {'enabled': False}}
                path = base / 'gitops/roots/public/values.yaml'
                path.parent.mkdir(parents=True)
                path.write_text(yaml.safe_dump(public))
                @contextmanager
                def snapshot(settings):
                    if unavailable: raise ValueError('Selected source unavailable')
                    yield package.ROOT / 'platform/delivery/services'
                    path.write_text(yaml.safe_dump(dict(public, services={'revision': 'b' * 40})))
                with patch.object(payload, 'ROOT', base), patch.object(payload, 'committed_payload', return_value={'repository': public['repository']}), \
                        patch.object(payload, 'dotenv_values', return_value={'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}), \
                        patch.object(owner, 'chart', side_effect=snapshot), \
                        patch.object(payload, 'catalog', return_value=({'catalog': [], 'dataApprovals': {}}, 'c' * 40)) as private_read:
                    with self.assertRaises(ValueError): payload.payload()
                    self.assertEqual(private_read.call_count, int(not unavailable))

    def test_exact_policy_set_rejects_extra_missing_foreign_or_broadened_authority(self):
        entry = {'definition': definition(), 'approval': approval()}
        desired = policies()['platform-workloads']
        actual = copy.deepcopy(desired)
        actual['metadata']['annotations'] = {'argocd.argoproj.io/tracking-id':
            'cloudlab-services:security.istio.io/AuthorizationPolicy:cloudlab-app-synthetic/platform-workloads'}
        cases = [[]]
        changed = copy.deepcopy(actual)
        changed['spec']['rules'][0]['to'][0]['operation']['ports'].append('8081')
        cases.append([changed])
        changed = copy.deepcopy(actual)
        changed['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = 'foreign'
        cases.append([changed])
        extra = copy.deepcopy(actual)
        extra['metadata']['name'] = 'unexpected-owned-allow'
        cases.append([actual, extra])
        for rows in cases:
            with self.subTest(rows=rows), patch.object(transport, 'get', return_value={'items': rows}):
                with self.assertRaises(RuntimeError): transport.policy(entry, [desired])
        malformed = copy.deepcopy(desired)
        malformed['metadata']['namespace'] = 'unrelated'
        with patch.object(transport, 'get') as get:
            with self.assertRaises(RuntimeError): transport.policy(entry, [malformed])
            get.assert_not_called()

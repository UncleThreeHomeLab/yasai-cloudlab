import copy
import os
from pathlib import Path
import subprocess
import tempfile
import sys
from types import SimpleNamespace
import json
import unittest
from unittest.mock import patch
from fixtures import approval, catalog, Keycloak
from playbooks.previews.files.contract import canonical, digest, names
from playbooks.keycloak.files import preview_clients as identity


class IdentityTests(unittest.TestCase):
    def test_obsolete_client_is_disabled_then_uuid_deleted_with_or_without_catalog(self):
        from playbooks.previews.files import contract
        for available in (True, False):
            row, settings, api = approval(), catalog(), Keycloak()
            intent = {'format': 1, 'entries': {row['instance']: {'phase': 'pending', 'approvalDigest': digest(canonical(row))}}}
            state = {'format': 1, 'entries': {}}
            identity.reconcile(settings, intent, state, api, lambda value: None, 1500, set())
            with patch.object(contract, 'IMAGE', 'python:3.13-slim-bookworm@sha256:' + 'd' * 64):
                identity.reconcile(settings if available else None, intent if available else None,
                                   state, api, lambda value: None, 1501, set(), input_available=available)
                self.assertFalse(api.rows['owned-client-uuid']['enabled'])
                self.assertEqual(state['entries'][row['instance']]['approvalDigest'], digest(canonical(row)))
                identity.reconcile(settings if available else None, intent, state, api, lambda value: None,
                                   2101, set(), input_available=available)
            self.assertEqual(api.deleted, ['owned-client-uuid'])
            self.assertEqual(state['entries'][row['instance']]['phase'], 'retired')

    def test_expired_or_retiring_client_cleanup_ignores_new_callback_hostname(self):
        for phase, now in (('active', 2000), ('retiring', 1501)):
            row, settings, api = approval(), catalog(), Keycloak()
            intent = {'format': 1, 'entries': {row['instance']: {'phase': 'pending', 'approvalDigest': digest(canonical(row))}}}
            state = {'format': 1, 'entries': {}}
            identity.reconcile(settings, intent, state, api, lambda value: None, 1500, set())
            settings['hostname'] = 'changed.internal.example.invalid'
            with self.assertRaises(ValueError):
                identity.reconcile(settings, intent, state, api, lambda value: None, 1501, set())
            state['entries'][row['instance']]['phase'] = phase
            identity.reconcile(settings, intent, state, api, lambda value: None, now, set())
            self.assertFalse(api.rows['owned-client-uuid']['enabled'])
            identity.reconcile(settings, intent, state, api, lambda value: None, now + 600, set())
            self.assertEqual(api.deleted, ['owned-client-uuid'])

    def test_obsolete_new_or_creating_row_never_creates_or_reactivates_client(self):
        from playbooks.previews.files import contract
        row, settings, api = approval(), catalog(), Keycloak()
        intent = {'format': 1, 'entries': {row['instance']: {'phase': 'pending', 'approvalDigest': digest(canonical(row))}}}
        state = {'format': 1, 'entries': {}}
        with patch.object(contract, 'IMAGE', 'python:3.13-slim-bookworm@sha256:' + 'd' * 64):
            identity.reconcile(settings, intent, state, api, lambda value: None, 1500, set())
            self.assertEqual(state['entries'], {})
            self.assertEqual(api.rows, {})
        identity.reconcile(settings, intent, state, api, lambda value: None, 1500, set())
        state['entries'][row['instance']]['phase'] = 'creating'
        api.rows.clear()
        with patch.object(contract, 'IMAGE', 'python:3.13-slim-bookworm@sha256:' + 'd' * 64):
            identity.reconcile(None, None, state, api, lambda value: None, 1501, set(), input_available=False)
        self.assertEqual(api.rows, {})
        self.assertEqual(state['entries'][row['instance']]['phase'], 'retired')

    def test_image_change_keeps_client_uuid_and_persistent_collision_vetoes(self):
        from playbooks.previews.files import contract
        for change in ('uuid', 'persistent'):
            row, settings, api = approval(), catalog(), Keycloak()
            intent = {'format': 1, 'entries': {row['instance']: {'phase': 'pending', 'approvalDigest': digest(canonical(row))}}}
            state = {'format': 1, 'entries': {}}
            identity.reconcile(settings, intent, state, api, lambda value: None, 1500, set())
            if change == 'uuid':
                api.rows['owned-client-uuid']['id'] = 'replacement-client'
            persistent = {names(row)['client']} if change == 'persistent' else set()
            with patch.object(contract, 'IMAGE', 'python:3.13-slim-bookworm@sha256:' + 'd' * 64), self.assertRaises(ValueError):
                identity.reconcile(None, None, state, api, lambda value: None, 1501, persistent, input_available=False)
            self.assertTrue(api.rows['owned-client-uuid']['enabled'])
            self.assertEqual(api.deleted, [])

    def test_runtime_adapter_retains_then_expires_clients_when_approval_input_disappears(self):
        from playbooks.previews.files import contract
        for corrupt, image_changed in ((False, False), (True, False), (False, True), (True, True)):
            row, settings, api = approval(), catalog(), Keycloak()
            intent = {'format': 1, 'entries': {row['instance']: {'phase': 'pending', 'approvalDigest': digest(canonical(row))}}}
            state = {'format': 1, 'entries': {}}
            identity.reconcile(settings, intent, state, api, lambda value: None, 1500, set())
            api.rows['unrelated'] = {'id': 'unrelated', 'clientId': 'persistent-client'}
            documents = {
                'cloudlab-preview-state': {'metadata': {'labels': {'cloudlab.io/owner': 'cloudlab-previews'}}, 'data': {'state.json': json.dumps(intent)}},
                'cloudlab-preview-identity-state': {'metadata': {'labels': {'cloudlab.io/owner': 'cloudlab-preview-identity'}}, 'data': {'state.json': json.dumps(state)}}}
            if corrupt:
                documents['cloudlab-preview-approvals'] = {'metadata': {'labels': {'cloudlab.io/owner': 'cloudlab-previews'}}, 'data': {'catalog.json': '{'}}
            def kube(method, path, value=None):
                name = path.rsplit('/', 1)[-1]
                if method == 'GET':
                    if name not in documents:
                        from urllib.error import HTTPError
                        raise HTTPError(path, 404, '', None, None)
                    return copy.deepcopy(documents[name])
                documents['cloudlab-preview-identity-state'] = copy.deepcopy(value)
                return copy.deepcopy(value)
            original = identity.reconcile
            def reconcile(settings, intent, state, adapter, save, now, persistent, **kwargs):
                return original(settings, intent, state, api, save, now, persistent, **kwargs)
            def read(path, *args, **kwargs):
                return json.dumps({'realms': {}}) if str(path) == '/private/desired_state' else 'synthetic-writer-secret'
            with patch.dict(sys.modules, {'lease': SimpleNamespace(api_request=kube),
                    'configuration': SimpleNamespace(private_request=lambda *args, **kwargs: {'access_token': 'synthetic'})}), \
                    patch.object(identity, 'reconcile', side_effect=reconcile), patch.object(Path, 'read_text', read), \
                    patch.object(contract, 'IMAGE', 'python:3.13-slim-bookworm@sha256:' + 'd' * 64 if image_changed else contract.IMAGE):
                for now in (1501, 2000, 2600):
                    with patch.object(identity.time, 'time', return_value=now), self.assertRaises(RuntimeError):
                        identity.run('identity-admin.internal.example.invalid')
                    if now == 1501: self.assertEqual(api.rows['owned-client-uuid']['enabled'], not image_changed)
            self.assertEqual(api.deleted, ['owned-client-uuid'])
            self.assertEqual(set(api.rows), {'unrelated'})

    def test_disable_confirm_grace_and_exact_removal_without_git(self):
        row = approval()
        settings = catalog()
        intent = {'format': 1, 'entries': {row['instance']: {'phase': 'pending', 'approvalDigest': digest(canonical(row))}}}
        state = {'format': 1, 'entries': {}}
        api = Keycloak()
        saves = []
        save = lambda value: saves.append(copy.deepcopy(value))
        identity.reconcile(settings, intent, state, api, save, 1500, set())
        self.assertEqual(state['entries'][row['instance']]['phase'], 'active')
        self.assertEqual(next(iter(api.rows.values()))['redirectUris'], ['https://preview.internal.example.invalid/previews/' + row['instance'] + '/callback'])
        identity.reconcile(None, None, state, api, save, 2000, set())
        self.assertFalse(next(iter(api.rows.values()))['enabled'])
        self.assertEqual(state['entries'][row['instance']]['disabledAt'], 2000)
        identity.reconcile(None, None, state, api, save, 2599, set())
        self.assertEqual(api.deleted, [])
        identity.reconcile(None, None, state, api, save, 2600, set())
        self.assertEqual(api.deleted, ['owned-client-uuid'])
        identity.reconcile(settings, intent, state, api, save, 1501, set())
        self.assertEqual(api.rows, {})
        self.assertEqual(state['entries'][row['instance']]['phase'], 'retired')

    def test_uuid_change_and_persistent_collision_never_adopted(self):
        row = approval()
        settings = catalog()
        intent = {'format': 1, 'entries': {row['instance']: {'phase': 'pending', 'approvalDigest': digest(canonical(row))}}}
        state = {'format': 1, 'entries': {}}
        api = Keycloak()
        with self.assertRaises(ValueError): identity.reconcile(settings, intent, state, api, lambda x: None, 1500, {names(row)['client']})
        self.assertEqual(api.rows, {})
        identity.reconcile(settings, intent, state, api, lambda x: None, 1500, set())
        api.rows['owned-client-uuid']['id'] = 'replacement'
        with self.assertRaises(ValueError): identity.reconcile(None, None, state, api, lambda x: None, 2600, set())
        self.assertEqual(api.deleted, [])

    def test_preview_failure_returns_for_ordinary_realm_repair_then_marks_failure(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(identity, 'run', side_effect=RuntimeError('private failure')):
            self.assertFalse(identity.attempt('identity-admin.internal.example.invalid', directory))
            self.assertEqual(Path(directory, 'preview-error').read_text(), 'Preview identity reconciliation failed; diagnostics withheld\n')

    def test_rendered_writer_repairs_both_realms_before_reporting_preview_failure(self):
        from playbooks.keycloak.files.chart import render
        objects = render({'enabled': True, 'operatorEnabled': False, 'reconciliationEnabled': True,
            'privateStateEnabled': True, 'trustedProxyAddresses': ['10.43.0.10/32'], 'databaseCA': 'fixture-ca'})
        job = next(obj for obj in objects if obj['kind'] == 'Job' and obj['metadata']['name'] == 'identity-reconcile-sync')
        script = job['spec']['template']['spec']['containers'][0]['args'][0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            imports, credentials, binary = (root / part for part in ('imports', 'credentials', 'bin'))
            for path in (imports, credentials, binary): path.mkdir()
            for realm in ('platform', 'applications'):
                credentials.joinpath(realm + '_client_secret').write_text('synthetic-' + 'x' * 48)
            with patch.object(identity, 'run', side_effect=RuntimeError('unavailable')):
                self.assertFalse(identity.attempt('identity-admin.internal.example.invalid', str(imports)))
            java = binary / 'java'
            java.write_text('#!/bin/sh\nprintf "%s\\n" "$KEYCLOAK_LOGINREALM" >> "$REALM_LOG"\n')
            java.chmod(0o700)
            script = script.replace('/imports', str(imports)).replace('/credentials', str(credentials)).replace('/tmp/result', str(root / 'result'))
            result = subprocess.run(['sh', '-ec', script], env=dict(os.environ, PATH=str(binary) + ':' + os.environ['PATH'],
                REALM_LOG=str(root / 'realms')), capture_output=True, text=True, timeout=10)
            self.assertEqual((root / 'realms').read_text().splitlines(), ['platform', 'applications'])
            self.assertEqual(result.returncode, 1)
            self.assertIn('ordinary realm repair completed', result.stdout)

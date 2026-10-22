from pathlib import Path
import subprocess
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from playbooks.harbor.files.chart import check, render
from playbooks.harbor.files.configuration import client
from playbooks.harbor.files.installation_credentials import definitions, signing_material, htpasswd
from playbooks.harbor.files.payload import compile_payload


class InstallationTests(unittest.TestCase):
    def test_chart_is_deterministic_bounded_and_contains_no_generated_secrets(self):
        result = check()
        self.assertEqual(result['immutable_bootstrap_images'], 9)
        self.assertEqual(result['independent_claims'], 3)

    def test_internal_database_uses_the_external_secret_without_a_shared_database(self):
        objects = render()
        database = next(obj for obj in objects if obj['kind'] == 'StatefulSet' and
                        obj['metadata']['labels'].get('component') == 'database')
        self.assertEqual(database['spec']['template']['spec']['containers'][0]['envFrom'],
                         [{'secretRef': {'name': 'harbor-database'}}])
        self.assertEqual(database['spec']['template']['spec']['volumes'][-1]['persistentVolumeClaim']['claimName'],
                         'harbor-database')

    def test_sdk_delivery_extracts_items_before_mapping_fields(self):
        external = [obj for obj in render('', {'enabled': True}) if obj['kind'] == 'ExternalSecret']
        self.assertEqual(len(external), 8)
        self.assertNotIn('harbor-recovery-signer', str(external))
        for obj in external:
            self.assertNotIn('data', obj['spec'])
            self.assertEqual(len(obj['spec']['dataFrom']), 1)
            self.assertEqual(set(obj['spec']['dataFrom'][0]), {'extract'})

    def test_cold_capture_can_stop_every_writer_through_chart_owned_replicas(self):
        values = {'harbor': {name: {'replicas': 0} for name in ('core', 'portal', 'nginx', 'jobservice', 'registry')}}
        values['harbor'].update(database={'internal': {'replicas': 0}}, redis={'internal': {'replicas': 0}})
        workloads = [obj for obj in render(runtime=values) if obj['kind'] in ('Deployment', 'StatefulSet')]
        self.assertEqual(len(workloads), 7)
        self.assertTrue(all(obj['spec']['replicas'] == 0 for obj in workloads))

    def test_storage_is_retained_and_does_not_inherit_uncoordinated_backup_jobs(self):
        objects = render('', {'enabled': True})
        storage = next(obj for obj in objects if obj['kind'] == 'StorageClass')
        self.assertEqual(storage['reclaimPolicy'], 'Retain')
        self.assertEqual(storage['parameters']['recurringJobSelector'], '[{"name":"harbor-coordinated","isGroup":true}]')
        self.assertEqual(storage['parameters']['numberOfReplicas'], '2')
        for obj in objects:
            if obj['kind'] == 'PersistentVolumeClaim':
                self.assertEqual(obj['metadata']['annotations']['argocd.argoproj.io/sync-options'], 'Prune=false,Delete=false')

    def test_signing_key_and_certificate_match_and_do_not_depend_on_a_host(self):
        material = signing_material()
        private = serialization.load_pem_private_key(material['tls_key'].encode(), password=None)
        certificate = x509.load_pem_x509_certificate(material['tls_crt'].encode())
        self.assertEqual(private.public_key().public_numbers(), certificate.public_key().public_numbers())
        self.assertEqual(private.key_size, 4096)
        result = subprocess.run(['openssl', 'rsa', '-traditional'], input=material['tls_key'].encode(), capture_output=True)
        self.assertEqual(result.returncode, 0, 'Native RSA encoding conversion failed')
        self.assertTrue(result.stdout.startswith(b'-----BEGIN RSA PRIVATE KEY-----'))
        converted = serialization.load_pem_private_key(result.stdout, password=None)
        self.assertTrue(private.private_numbers() == converted.private_numbers())

    def test_token_key_conversion_preserves_vault_source_and_uses_only_memory(self):
        core = next(obj for obj in render() if obj['kind'] == 'Deployment' and
                    obj['metadata']['labels'].get('component') == 'core')['spec']['template']['spec']
        init = next(container for container in core['initContainers'] if container['name'] == 'token-key-format')
        self.assertEqual(init['image'], core['containers'][0]['image'])
        self.assertIn('umask 077; exec openssl rsa -traditional', init['command'][-1])
        self.assertEqual(init['volumeMounts'][0], {'name': 'token-service-private-key', 'mountPath': '/source', 'readOnly': True})
        volumes = {volume['name']: volume for volume in core['volumes']}
        self.assertEqual(volumes['token-service-private-key']['secret']['secretName'], 'harbor-token-signing')
        self.assertEqual(volumes['psc']['emptyDir'], {'medium': 'Memory', 'sizeLimit': '1Mi'})
        mount = next(mount for mount in core['containers'][0]['volumeMounts'] if mount['mountPath'] == '/etc/core/private_key.pem')
        self.assertEqual(mount, {'name': 'psc', 'mountPath': '/etc/core/private_key.pem', 'subPath': 'registry-private-key.pem', 'readOnly': True})

    def test_registry_password_and_bcrypt_are_generated_once_per_definition(self):
        fields = definitions()['harbor-runtime']
        first = fields['REGISTRY_PASSWD'][1]()
        self.assertEqual(first, fields['REGISTRY_PASSWD'][1]())
        self.assertTrue(htpasswd(first).startswith('harbor_registry_user:$2'))

    def test_oidc_contract_rejects_public_routes_wrong_issuer_and_callback_paths(self):
        contract = client('https://login.example.invalid/realms/platform', 'https://harbor.internal.example.invalid')
        self.assertEqual(contract['callbacks'], ['https://harbor.internal.example.invalid/c/oidc/callback',
                                                 'https://harbor.internal.example.invalid/oauth2/callback'])
        self.assertFalse(contract['public'])
        for issuer, origin in (
            ('https://login.example.invalid/realms/applications', 'https://harbor.internal.example.invalid'),
            ('https://login.other.invalid/realms/platform', 'https://harbor.internal.example.invalid'),
            ('https://login.example.invalid/realms/platform', 'https://harbor.example.invalid'),
            ('https://login.example.invalid/realms/platform', 'https://harbor.internal.example.invalid/extra')):
            with self.assertRaises(ValueError): client(issuer, origin)

    def test_machine_routes_strip_cookies_and_browser_sessions_have_no_refresh(self):
        objects = render('', {'enabled': True})
        route = next(obj for obj in objects if obj['kind'] == 'HTTPRoute')
        machine, browser = route['spec']['rules']
        self.assertEqual(machine['filters'], [{'type': 'RequestHeaderModifier', 'requestHeaderModifier': {'remove': ['Cookie']}}])
        self.assertTrue(all(match['path']['value'] in ('/v2', '/service/token', '/api/v2.0') for match in machine['matches']))
        self.assertEqual(browser['backendRefs'][0]['name'], 'harbor-browser')
        gate = next(obj for obj in objects if obj['kind'] == 'Deployment')
        arguments = gate['spec']['template']['spec']['containers'][0]['args']
        self.assertIn('--cookie-expire=240s', arguments)
        self.assertIn('--cookie-refresh=0', arguments)
        self.assertIn('--code-challenge-method=S256', arguments)

    def test_payload_binds_only_the_private_origin_to_the_retained_issuer(self):
        payload = compile_payload({'repository': 'https://github.com/fixture/platform.git', 'revision': 'a' * 40},
                                  {'loginHost': 'login.example.invalid', 'gatewayIP': '10.43.0.100'})
        self.assertEqual(payload['configuration']['harborHost'], 'harbor.internal.example.invalid')
        self.assertEqual(payload['identity_client']['id'], 'harbor')
        self.assertEqual(payload['server']['harbor']['core']['hostAliases'],
                         [{'ip': '10.43.0.100', 'hostnames': ['login.example.invalid']}])
        core = next(obj for obj in render('server', payload['server']) if obj['kind'] == 'Deployment' and
                    obj['metadata']['labels'].get('component') == 'core')
        self.assertEqual(core['spec']['template']['spec']['hostAliases'],
                         [{'ip': '10.43.0.100', 'hostnames': ['login.example.invalid']}])

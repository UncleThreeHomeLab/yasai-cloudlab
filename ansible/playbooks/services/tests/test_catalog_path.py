"""One reviewed owner/path selection; inactive inputs cannot change active state."""
import unittest
from unittest.mock import Mock, patch

from playbooks.argocd.files import private_publish, service_activation
from playbooks.services.files import catalog, owner, source
from playbooks.services.tests.fixtures import catalog_application, catalog_payload


class CatalogPathTests(unittest.TestCase):
    def test_bounded_paths_default_only_when_omitted(self):
        self.assertEqual(service_activation.catalog_path(), 'services/catalog.json')
        for path in ('services/catalog-v2.yaml', 'services/catalog-team-2.json'):
            self.assertEqual(service_activation.catalog_path(path), path)
        for path in (None, '', '../catalog.yaml', 'services/../catalog.yaml', 'services/nested/catalog.yaml',
                     'identity/argo-values.yaml', 'services/catalog.yaml?ref=main', 'services/catalog.yml'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                service_activation.catalog_path(path)

    def test_inactive_catalog_does_not_change_active_application_and_handoff_is_one_source_pair(self):
        legacy = catalog_payload()
        old = catalog_application(legacy)
        # Merely preparing another private file does not change the reviewed selection.
        self.assertEqual(catalog_application(legacy), old)
        new = dict(legacy, revision='c' * 40, catalogPath='services/catalog-v2.yaml')
        app = catalog_application(new)
        self.assertEqual(app['metadata']['name'], old['metadata']['name'])
        self.assertEqual(app['spec']['sources'][0]['targetRevision'], new['revision'])
        self.assertEqual(app['spec']['sources'][0]['helm']['valueFiles'][0], '$values/services/catalog-v2.yaml')
        self.assertEqual(app['spec']['sources'][1], old['spec']['sources'][1])
        self.assertTrue(service_activation.sources_match(old, legacy))
        self.assertFalse(service_activation.sources_match(app, legacy))
        self.assertFalse(service_activation.sources_match(old, new))
        with patch.object(catalog, 'get', return_value=app):
            self.assertTrue(catalog.converged(new))
            self.assertFalse(catalog.converged(legacy))
        # A legacy receipt with no path can attest only the legacy source.
        target = {'valuesRepository': new['private_repository'], 'valuesRevision': new['private_revision']}
        evidence = service_activation.prepare({'repository': new['repository'], 'services': {
            'enabled': True, 'revision': new['revision'], 'catalogPath': new['catalogPath']},
            'observability': {'enabled': new['telemetry']}}, target['valuesRepository'], target['valuesRevision'], new['values'])
        from playbooks.admission.files.namespace_guard import authority, namespace_guard_desired
        documents = namespace_guard_desired(evidence['namespaceGuard'])
        for obj in documents:
            obj['metadata'].update(uid=obj['kind'] + '-uid', generation=1)
        with patch('playbooks.admission.files.namespace_guard.qualify', return_value=authority(documents)):
            checked = service_activation.guard(evidence, target,
                lambda kind, name: app if name == 'cloudlab-services' else None, probe=lambda obj: (0, ''))
            app['spec']['sources'][0]['helm']['valueFiles'][0] = '$values/services/catalog.json'
            with self.assertRaises(RuntimeError):
                service_activation.guard(checked, target,
                    lambda kind, name: app if name == 'cloudlab-services' else None, probe=lambda obj: (0, ''))

    def test_publisher_cannot_update_an_inactive_catalog(self):
        api = Mock()
        with patch.object(private_publish, 'inspect', return_value={}), \
                patch.object(owner, 'configuration', return_value={'catalogPath': 'services/catalog-v2.yaml'}):
            with self.assertRaisesRegex(ValueError, 'bounded owner bundle'):
                private_publish.publish(api, {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'},
                                        {'services/catalog.json': '{}'}, scope='services')
        api.request.assert_not_called()

    def test_yaml_publisher_reads_and_writes_only_selected_active_path(self):
        value = {'catalog': [], 'dataApprovals': {}}
        api = Mock()
        import base64
        import yaml
        api.request.side_effect = [{'object': {'sha': 'b' * 40}},
                                  {'content': base64.b64encode(yaml.safe_dump(value).encode()).decode()}]
        public = {'repository': 'https://github.com/example/platform.git',
                  'services': {'revision': 'a' * 40, 'catalogPath': 'services/catalog-v2.yaml'}}
        with patch.object(source, 'WRITER', ({'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}, api)), \
                patch('playbooks.services.files.inputs.validate_catalog', return_value=value), \
                patch('pathlib.Path.read_text', return_value=yaml.safe_dump(public)), \
                patch.object(private_publish, 'publish', return_value={'private_source_changed': False}) as publish:
            source.publish(value, expected=value)
        self.assertIn('/contents/services/catalog-v2.yaml?ref=' + 'b' * 40, api.request.call_args.args[1])
        self.assertEqual(set(publish.call_args.args[2]), {'services/catalog-v2.yaml'})

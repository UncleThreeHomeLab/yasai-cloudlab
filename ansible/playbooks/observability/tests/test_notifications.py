"""Reviewed notification inputs resolve to bounded native configuration."""
import base64
import copy
from pathlib import Path
import tarfile
import unittest

import yaml

from playbooks.observability.files.chart import render, configuration
from playbooks.observability.tests.fixtures import native_source_inputs, notification_inputs, notification_application as native_notifications


class NotificationTests(unittest.TestCase):
    def test_disabled_delivery_is_explicit_and_native_storage_does_not_switch_legacy(self):
        app = native_notifications(native_source_inputs())
        self.assertEqual(app['metadata']['annotations']['cloudlab.io/notification-delivery'], 'unconfigured')
        overrides = app['spec']['sources'][0]['helm']['valuesObject']
        native = overrides['kube-prometheus-stack']['alertmanager']
        self.assertEqual(native['config']['receivers'], [{'name': 'unconfigured'}])
        objects = render('prometheus', overrides)
        manager = next(obj['spec'] for obj in objects if obj['kind'] == 'Alertmanager')
        self.assertIsNone(manager['storage'].get('emptyDir'))
        claim = manager['storage']['volumeClaimTemplate']
        self.assertEqual(claim['spec']['resources']['requests']['storage'], '1Gi')
        self.assertEqual(claim['spec']['storageClassName'], 'cloudlab-telemetry')
        self.assertEqual(manager['persistentVolumeClaimRetentionPolicy'],
                         {'whenDeleted': 'Retain', 'whenScaled': 'Retain'})
        archive = Path(__file__).resolve().parents[4] / 'platform/observability/prometheus/charts/kube-prometheus-stack-92.3.1.tgz'
        with tarfile.open(archive) as source:
            crd = yaml.safe_load(source.extractfile('kube-prometheus-stack/charts/crds/crds/crd-alertmanagers.yaml'))
        schema = next(version for version in crd['spec']['versions'] if version['name'] == 'v1')['schema']['openAPIV3Schema']
        retention = schema['properties']['spec']['properties']['persistentVolumeClaimRetentionPolicy']['properties']
        self.assertEqual(set(retention), {'whenDeleted', 'whenScaled'})
        legacy = next(obj['spec'] for obj in render('prometheus') if obj['kind'] == 'Alertmanager')
        self.assertEqual(legacy['storage'], {'emptyDir': {'sizeLimit': '64Mi'}})
        boundaries = configuration(True)
        quota = next(obj for obj in boundaries if obj['kind'] == 'ResourceQuota')
        self.assertEqual(quota['spec']['hard']['requests.storage'], '71Gi')
        self.assertEqual(quota['spec']['hard']['persistentvolumeclaims'], '5')
        storage = next(obj for obj in boundaries if obj['kind'] == 'StorageClass')
        self.assertEqual(storage['reclaimPolicy'], 'Retain')

    def test_catalog_destination_authentication_and_fanout_reach_native_config(self):
        app = native_notifications(notification_inputs())
        overrides = app['spec']['sources'][0]['helm']['valuesObject']
        objects = render('prometheus', overrides)
        secret = next(obj for obj in objects if obj['kind'] == 'Secret' and
                      obj['metadata']['name'] == 'alertmanager-cloudlab')
        config = yaml.safe_load(base64.b64decode(secret['data']['alertmanager.yaml']))
        receivers = {row['name']: row for row in config['receivers']}
        webhook = receivers['primary']['webhook_configs'][0]
        self.assertEqual(webhook['url'],
            'https://incident-receiver.cloudlab-app-incident-receiver.svc:9443/alerts/primary')
        self.assertTrue(webhook['send_resolved'])
        http = webhook['http_config']
        self.assertFalse(http['follow_redirects'])
        self.assertEqual(http['authorization']['credentials_file'],
            '/etc/alertmanager/secrets/alertmanager-notification-fixture/token')
        self.assertNotIn('insecure_skip_verify', http['tls_config'])
        self.assertEqual(len(config['route']['routes']), 6)
        self.assertTrue(all(route['continue'] for route in config['route']['routes']))
        self.assertEqual(config['route']['receiver'], 'operator-email')
        self.assertTrue(receivers['operator-email']['email_configs'][0]['require_tls'])
        manager = next(obj['spec'] for obj in objects if obj['kind'] == 'Alertmanager')
        self.assertEqual(manager['secrets'], ['alertmanager-notification-fixture'])

    def test_invalid_bindings_credentials_and_subscriptions_fail_before_rendering(self):
        cases = []
        for target, key, invalid in [
            ('target', 'service', 'foreign'), ('target', 'port', 'missing'),
            ('target', 'path', '/../admin'), ('target', 'path', '/alerts?token=value'),
            ('target', 'path', '/alerts%2fadmin'), ('target', 'path', '/alerts\r\nInjected'),
            ('authentication', 'credentials', 'inline-not-allowed')]:
            row = notification_inputs()
            row['platformNotifications']['receivers'][1]['webhook'][target][key] = invalid
            cases.append(row)
        for key, invalid in [('name', 'unrelated-secret'), ('key', '../token'), ('key', '..data')]:
            row = notification_inputs()
            row['platformNotifications']['receivers'][1]['webhook']['authentication']['secretRef'][key] = invalid
            cases.append(row)
        for change in ('retired', 'composition', 'chart', 'duplicate-port', 'udp'):
            row = notification_inputs()
            entry = row['catalog'][1]
            if change == 'retired': entry['publication'] = 'retired'
            elif change == 'composition': entry['approval']['composition'] = {}
            elif change == 'chart': entry['approval']['chartPath'] = 'apps/notes'
            elif change == 'duplicate-port': entry['definition']['ports'] *= 2
            else: entry['definition']['ports'][0]['protocol'] = 'UDP'
            cases.append(row)
        for change in ('disabled', 'fallback', 'unknown-receiver', 'duplicate-receiver',
                       'duplicate-subscription', 'unknown-service', 'inline-password', 'repeat-interval'):
            row = notification_inputs()
            value = row['platformNotifications']
            if change == 'disabled': value['enabled'] = False
            elif change == 'fallback': value['fallbackReceiver'] = ''
            elif change == 'unknown-receiver': value['subscriptions'][0]['receivers'] = ['missing']
            elif change == 'duplicate-receiver': value['receivers'].append(copy.deepcopy(value['receivers'][0]))
            elif change == 'duplicate-subscription': value['subscriptions'] *= 2
            elif change == 'unknown-service': value['subscriptions'][0]['service'] = 'foreign'
            elif change == 'repeat-interval': value.update(groupIntervalSeconds=60, repeatIntervalSeconds=30)
            else: value['receivers'][0]['email']['password'] = 'inline-not-allowed'
            cases.append(row)
        for index, row in enumerate(cases):
            with self.subTest(case=index):
                with self.assertRaises(ValueError): native_notifications(row)

    def test_mesh_candidate_uses_no_shared_bearer_and_does_not_claim_delivery_readiness(self):
        value = notification_inputs()
        hook = value['platformNotifications']['receivers'][1]['webhook']
        hook['authentication'] = {'mode': 'mesh'}
        del hook['caSecretRef']
        app = native_notifications(value)
        config = app['spec']['sources'][0]['helm']['valuesObject']['kube-prometheus-stack']['alertmanager']['config']
        delivery = next(row for row in config['receivers'] if row['name'] == 'primary')['webhook_configs'][0]
        self.assertTrue(delivery['url'].startswith('http://incident-receiver.cloudlab-app-incident-receiver.svc:9443/'))
        self.assertEqual(delivery['http_config'], {'follow_redirects': False})
        self.assertEqual(app['metadata']['annotations']['cloudlab.io/notification-delivery'], 'candidate')

    def test_subscription_removal_retains_shared_receivers_and_state(self):
        value = notification_inputs()
        before = native_notifications(value)['spec']['sources'][0]['helm']['valuesObject']['kube-prometheus-stack']['alertmanager']
        value['platformNotifications']['subscriptions'] = []
        after = native_notifications(value)['spec']['sources'][0]['helm']['valuesObject']['kube-prometheus-stack']['alertmanager']
        self.assertEqual(after['config']['route']['routes'], [])
        self.assertEqual(before['config']['receivers'], after['config']['receivers'])
        self.assertEqual(before['alertmanagerSpec'], after['alertmanagerSpec'])


if __name__ == '__main__':
    unittest.main()

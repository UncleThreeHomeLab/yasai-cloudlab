import copy
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import urllib.error

from automation.observability.verify import backend_ready, storage, proxy, kiali_control_plane_permissions


class StorageBoundaryTests(unittest.TestCase):
    def test_kiali_transport_permission_checks_reject_missing_broad_or_unavailable_access(self):
        def scoped(*args, **kwargs):
            self.assertEqual(args[:5], ('auth', 'can-i', 'create', 'pods', '--subresource=portforward'))
            permitted = args[args.index('-n') + 1] == 'istio-system'
            return SimpleNamespace(returncode=0 if permitted else 1, stdout='yes\n' if permitted else 'no\n')
        with patch('automation.observability.verify.kube', side_effect=scoped):
            kiali_control_plane_permissions()
        for result in (SimpleNamespace(returncode=0, stdout='yes'),
                       SimpleNamespace(returncode=1, stdout='no'),
                       SimpleNamespace(returncode=1, stdout=''),
                       SimpleNamespace(returncode=2, stdout='')):
            with self.subTest(result=result), patch('automation.observability.verify.kube', return_value=result):
                with self.assertRaises(RuntimeError): kiali_control_plane_permissions()

    def test_queries_use_authenticated_private_proxy_and_reject_failed_responses(self):
        origin = 'https://grafana.internal.example.invalid'
        headers = {'Authorization': 'Basic fixture', 'Accept': 'application/json'}
        with patch('automation.observability.verify.direct_https', return_value=(200, b'{"data":{}}')) as request:
            self.assertEqual(proxy(origin, '10.43.0.1', headers, 'logs', '/loki/api/v1/query_range?limit=10'), {'data': {}})
            request.assert_called_once_with(origin + '/api/datasources/proxy/uid/logs/loki/api/v1/query_range?limit=10',
                                            '10.43.0.1', headers)
            with self.assertRaises(ValueError): proxy(origin, '10.43.0.1', headers, 'unapproved', '/')
            for status in (401, 403, 404, 503):
                request.return_value = (status, b'{"private_diagnostic":"withheld"}')
                with self.assertRaises(urllib.error.HTTPError) as error: proxy(origin, '10.43.0.1', headers, 'traces', '/api/traces/fixture')
                self.assertEqual(error.exception.code, status)
                self.assertNotIn('private_diagnostic', str(error.exception))

    def test_operator_backend_must_be_available_and_reconciled_at_current_generation(self):
        ready = {'metadata': {'generation': 3}, 'status': {'conditions': [
            {'type': name, 'status': 'True', 'observedGeneration': 3} for name in ('Available', 'Reconciled')]}}
        backend_ready(ready)
        for conditions in ([], [ready['status']['conditions'][0]],
                           [dict(row, status='False') for row in ready['status']['conditions']],
                           [dict(row, observedGeneration=2) for row in ready['status']['conditions']]):
            with self.assertRaises(RuntimeError):
                backend_ready({'metadata': {'generation': 3}, 'status': {'conditions': conditions}})
        with self.assertRaises(RuntimeError): backend_ready(None)

    def test_disposable_telemetry_cannot_inherit_monthly_or_individual_backup_jobs(self):
        claims = [{'status': {'phase': 'Bound'}, 'spec': {'storageClassName': 'cloudlab-telemetry',
                   'volumeName': 'fixture-' + str(index)}} for index in range(4)]
        volumes = {claim['spec']['volumeName']: {'metadata': {'labels': {
            'recurring-job-group.longhorn.io/telemetry-disposable': 'enabled'}}} for claim in claims}
        storage(claims, volumes)
        for label in ('recurring-job-group.longhorn.io/default', 'recurring-job.longhorn.io/monthly-backup'):
            inherited = copy.deepcopy(volumes)
            inherited['fixture-0']['metadata']['labels'][label] = 'enabled'
            with self.assertRaises(RuntimeError): storage(claims, inherited)
        with self.assertRaises(RuntimeError): storage(claims[:3], volumes)
        claims[0]['status']['phase'] = 'Pending'
        with self.assertRaises(RuntimeError): storage(claims, volumes)

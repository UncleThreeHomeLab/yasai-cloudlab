import copy
import unittest

from automation.observability.verify import backend_ready, storage


class StorageBoundaryTests(unittest.TestCase):
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

import copy
import unittest

from automation.observability.verify import storage


class StorageBoundaryTests(unittest.TestCase):
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

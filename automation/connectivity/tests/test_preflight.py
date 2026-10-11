"""Prerequisite failures aggregate without account mutations or secret disclosure."""
import json
import unittest
from unittest.mock import patch

from automation.connectivity import preflight


class PreflightTests(unittest.TestCase):
    def test_missing_credentials_and_cluster_errors_return_safe_blockers(self):
        with (patch.object(preflight, 'fields', side_effect=RuntimeError('private-provider-secret')),
             patch.object(preflight, 'ssh', side_effect=RuntimeError('private-host-secret')),
             patch.dict(preflight.os.environ, {'VM_HOST': 'private-host-secret'}, clear=True)):
            result = preflight.audit()
        self.assertFalse(result['ready'])
        self.assertFalse(result['cutover_authorized'])
        self.assertTrue(result['read_only'])
        self.assertNotIn('private-provider-secret', json.dumps(result))
        self.assertNotIn('private-host-secret', json.dumps(result))
        self.assertGreaterEqual(len(result['blockers']), 7)

    def test_healthy_apps_do_not_replace_accepted_ownership_handoffs(self):
        cluster = {key: True for key in ('gitops_ready', 'certificates_ready', 'gateways_ready', 'internal_gateways', 'host_tailscale_ready', 'gateway_api_traefik_owned')}
        cluster.update(gateway_api_crds=10, eso_receipt='released', mesh_receipt='accepted', longhorn_receipt='accepted', backup_receipt='accepted')
        with (patch.object(preflight, 'fields', side_effect=RuntimeError('unavailable')),
              patch.object(preflight, 'ssh', return_value=json.dumps(cluster)),
              patch.dict(preflight.os.environ, {'VM_HOST': 'fixture'}, clear=True)):
            result = preflight.audit()
        self.assertIn('Milestone 02 mesh or storage ownership handoff is not accepted', result['blockers'])
        self.assertFalse(result['cutover_authorized'])


if __name__ == '__main__':
    unittest.main()

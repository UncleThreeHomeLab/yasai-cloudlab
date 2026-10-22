"""Native Helm inventory preserves the exact pinned read-only chart expectations."""
import unittest

from playbooks.istio.tests.fixtures import COMPONENT, run_native
import chart


class NativeInventoryTests(unittest.TestCase):
    def test_native_helm_inventory_matches_the_existing_pinned_chart_checks(self):
        result, inventory = run_native([
            {'ansible.builtin.import_tasks': str(COMPONENT / 'tasks/native-inventory.yml')},
            {'ansible.builtin.copy': {'dest': '{{ fixture_output_path }}',
                'content': '{{ mesh_native_inventory | to_json }}', 'mode': '0600'}}],
            {'mesh_chart_components': ['base', 'istiod', 'cni', 'ztunnel']})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for component in ('base', 'istiod', 'cni', 'ztunnel'):
            self.assertEqual(inventory['mesh_objects'][component], chart.render(component))
        self.assertEqual(inventory['gateway_api'], chart.gateway_api())

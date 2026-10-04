import unittest
from render import payload, images


class RenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = payload()

    def test_private_api_and_no_implicit_role(self):
        objects = {x['metadata']['name']: x for x in self.data['operator'] if x['kind'] == 'ConfigMap'}
        self.assertEqual(objects['argocd-cm']['data']['admin.enabled'], 'false')
        self.assertEqual(objects['argocd-cm']['data']['users.anonymous.enabled'], 'false')
        self.assertEqual(objects['argocd-rbac-cm']['data']['policy.default'], 'role:no-access')
        self.assertTrue(all('@sha256:' in x for x in images(self.data['operator'])))

    def test_public_project_cannot_create_privileged_platform_objects(self):
        project = next(x['spec'] for x in self.data['roots'] if x['kind'] == 'AppProject' and x['metadata']['name'] == 'cloudlab-public')
        self.assertEqual(project['clusterResourceWhitelist'], [])
        self.assertEqual([x['namespace'] for x in project['destinations']], ['cloudlab-public'])
        denied = {'Secret', 'RoleBinding', 'Application', 'AppProject', 'ExternalSecret', 'Gateway'}
        self.assertFalse(denied & {x['kind'] for x in project['namespaceResourceWhitelist']})
        self.assertFalse(any('*' in x for x in project['sourceRepos']))

    def test_source_failure_or_application_removal_cannot_prune(self):
        for app in [x for x in self.data['roots'] if x['kind'] == 'Application']:
            self.assertFalse(app['spec']['syncPolicy']['automated']['prune'])
            self.assertNotIn('finalizers', app['metadata'])
            self.assertIn('FailOnSharedResource=true', app['spec']['syncPolicy']['syncOptions'])

    def test_server_has_no_broad_chart_ingress_policy(self):
        policies = [x for x in self.data['operator'] if x['kind'] == 'NetworkPolicy']
        self.assertTrue(any(x['metadata']['name'] == 'argocd-default-deny' for x in policies))
        self.assertFalse(any(rule == {} for x in policies for rule in x['spec'].get('ingress', [])))

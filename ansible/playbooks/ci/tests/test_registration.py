"""Verify native Git generators, retained private source and runner registration gates."""
import unittest

from playbooks.ci.tests.fixtures import render_root


class RegistrationTests(unittest.TestCase):
    def test_controller_uses_git_file_generator_and_project_scoped_read_only_source(self):
        objects = render_root()
        project = next(row for row in objects if row['kind'] == 'AppProject' and row['metadata']['name'] == 'cloudlab-ci')
        root = next(row for row in objects if row['kind'] == 'AppProject' and row['metadata']['name'] == 'cloudlab-root')
        self.assertIn({'group': 'argoproj.io', 'kind': 'ApplicationSet'}, root['spec']['namespaceResourceWhitelist'])
        self.assertIn('https://github.com/example/private-config.git', project['spec']['sourceRepos'])
        sets = [row for row in objects if row['kind'] == 'ApplicationSet' and
                row['metadata'].get('labels', {}).get('cloudlab.io/owner') == 'ci-platform']
        self.assertEqual([row['metadata']['name'] for row in sets], [
            'cloudlab-ci-controller', 'cloudlab-ci-application-controller', 'cloudlab-ci-application-runner',
            'cloudlab-ci-application-publisher'])
        controller = sets[0]
        generator, = controller['spec']['generators']
        self.assertEqual(generator['git']['files'], [{'path': 'platform/ci/config.json'}])
        self.assertEqual(generator['git']['revision'], 'main')
        self.assertEqual(controller['spec']['syncPolicy'], {
            'applicationsSync': 'create-update', 'preserveResourcesOnDeletion': True})
        private = next(row for row in objects if row['kind'] == 'ExternalSecret' and row['metadata']['name'] == 'cloudlab-ci-source')
        self.assertEqual(private['spec']['dataFrom'], [{'extract': {'key': 'github-argocd'}}])
        self.assertEqual(private['spec']['target']['template']['data']['project'], 'cloudlab-ci')

    def test_applications_use_one_generic_catalog_without_application_specific_installers(self):
        objects = render_root()
        for component, chart in (('controller', 'controller'), ('runner', 'pool'), ('publisher', 'pool')):
            application = next(row for row in objects if row['kind'] == 'ApplicationSet' and
                               row['metadata']['name'] == 'cloudlab-ci-application-' + component)
            self.assertEqual(application['spec']['generators'][0]['git']['files'],
                             [{'path': 'platform/ci/pools/*/' + component + '.json'}])
            source, = application['spec']['template']['spec']['sources']
            self.assertEqual(source['path'], 'platform/delivery/ci/' + chart)
            self.assertTrue(source['helm']['skipCrds'])
            self.assertEqual(source['helm']['values'], '{{ .values | toYaml }}')
            self.assertTrue(application['spec']['syncPolicy']['preserveResourcesOnDeletion'])

    def test_pool_is_separate_and_uses_indexed_images_without_replacing_the_profile(self):
        objects = render_root(pool=True)
        pool = next(row for row in objects if row['kind'] == 'ApplicationSet' and row['metadata']['name'] == 'cloudlab-ci-pool')
        spec = pool['spec']['template']['spec']
        self.assertEqual(spec['destination']['namespace'], 'cloudlab-ci-private')
        public, private = spec['sources']
        self.assertEqual(public['helm']['valueFiles'], ['values.json', '$values/platform/ci/config.json'])
        self.assertEqual(public['helm']['parameters'], [
            {'name': 'arc.template.spec.containers[0].image', 'value': '{{ .images.runner }}'},
            {'name': 'arc.template.spec.initContainers[0].image', 'value': '{{ .images.builder }}'}])
        self.assertEqual(private['targetRevision'], 'main')
        self.assertFalse(spec['syncPolicy']['automated']['prune'])

    def test_absent_private_source_cannot_emit_runner_applications_or_break_public_root(self):
        objects = render_root(pool=True, private=False)
        self.assertFalse(any(row['kind'] == 'ApplicationSet' and
            row['metadata'].get('labels', {}).get('cloudlab.io/owner') == 'ci-platform' for row in objects))

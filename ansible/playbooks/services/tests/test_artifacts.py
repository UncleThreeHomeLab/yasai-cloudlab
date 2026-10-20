"""Release generation and registry credentials stay inside administrator boundaries."""
import copy
import json
import subprocess
import tempfile
import unittest

import yaml

from playbooks.services.files.contract import ROOT
from playbooks.services.files.gitops import resources
from playbooks.services.tests.fixtures import approval, definition


class ArtifactTests(unittest.TestCase):
    def test_complete_catalog_validates_artifact_against_its_configured_platform_repository(self):
        from playbooks.services.files.inputs import validate_catalog
        value, allowed = self.inputs()
        repository = yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())['repository']
        organization = repository.removeprefix('https://github.com/').split('/')[0]
        allowed['artifact']['sourceRepository'] = organization + '/producer'
        allowed['artifact']['identities'] = [repository.removesuffix('.git') +
            '/.github/workflows/application-publish.yaml@' + 'a' * 40]
        catalog = {'catalog': [{'definition': value, 'approval': allowed, 'publication': 'ready'}], 'dataApprovals': {}}
        self.assertEqual(validate_catalog(catalog), catalog)
        allowed['artifact']['sourceRepository'] = 'foreign/producer'
        with self.assertRaises(ValueError): validate_catalog(catalog)

    def test_policy_matches_pinned_api_and_native_cli_blocks_other_registries_in_all_container_types(self):
        from playbooks.admission.files.chart import render
        import jsonschema
        value, allowed = self.inputs()
        policy = next(o for o in self.render(value, allowed) if o['kind'] == 'Policy')
        installed = render()
        crd = next(o for o in installed if o['kind'] == 'CustomResourceDefinition' and
                   o['metadata']['name'] == 'policies.kyverno.io')
        schema = next(v for v in crd['spec']['versions'] if v['name'] == 'v1')['schema']['openAPIV3Schema']
        jsonschema.validate(policy, schema)
        binding = next(o for o in self.render(value, allowed) if o['kind'] == 'RoleBinding')
        accounts = {o['spec']['template']['spec']['serviceAccountName'] for o in installed
                    if o['kind'] == 'Deployment'}
        self.assertIn(binding['subjects'][0]['name'], accounts)
        pods = [{'apiVersion': 'v1', 'kind': 'Pod',
                 'metadata': {'name': 'bootstrap', 'namespace': allowed['namespace']},
                 'spec': {'containers': [{'name': 'application', 'image': value['image']}]}}]
        for field in ('containers', 'initContainers', 'ephemeralContainers'):
            pod = copy.deepcopy(pods[0])
            pod['metadata']['name'] = field.lower()
            pod['spec'][field] = [{'name': 'unapproved', 'image': 'unapproved.example.invalid/application@sha256:' + 'a' * 64}]
            pods.append(pod)
        with tempfile.TemporaryDirectory() as temporary:
            from pathlib import Path
            directory = Path(temporary)
            (directory / 'policy.yaml').write_text(yaml.safe_dump(policy))
            (directory / 'pods.yaml').write_text(yaml.safe_dump_all(pods))
            (directory / 'kyverno-test.yaml').write_text(yaml.safe_dump({
                'apiVersion': 'cli.kyverno.io/v1alpha1', 'kind': 'Test', 'metadata': {'name': 'registry-boundary'},
                'policies': ['policy.yaml'], 'resources': ['pods.yaml'],
                'results': [{'policy': 'application-artifacts', 'rule': 'approved-repositories',
                             'resources': [pod['metadata']['name']], 'kind': 'Pod',
                             'result': 'pass' if i == 0 else 'fail'} for i, pod in enumerate(pods)]}))
            result = subprocess.run(['kyverno', 'test', str(directory)], capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def inputs(self):
        allowed = approval()
        allowed['artifact'] = {
            'repository': 'registry.example.invalid/cloudlab-public/synthetic',
            'project': 'cloudlab-public', 'releasePath': 'apps/releases/synthetic.json',
            'sourceRepository': 'example/producer', 'action': 'Audit',
            'identities': ['https://github.com/example/platform/.github/workflows/application-publish.yaml@' + 'a' * 40]}
        return definition(), allowed

    def render(self, value, allowed):
        return resources(value, allowed, 'https://github.com/example/platform.git', 'b' * 40)

    def test_release_uses_native_git_generator_and_scoped_read_only_pull_credentials(self):
        value, allowed = self.inputs()
        original = copy.deepcopy(value)
        objects = self.render(value, allowed)
        application = next(o for o in objects if o['kind'] == 'ApplicationSet')
        self.assertEqual(application['spec']['generators'], [{'git': {
            'repoURL': allowed['repository'], 'revision': 'main',
            'files': [{'path': 'apps/releases/synthetic.json'}]}}])
        template = application['spec']['template']
        self.assertEqual(template['metadata']['name'], 'synthetic-' + value['name'])
        desired = template['spec']['sources'][0]['helm']['valuesObject']
        self.assertEqual(desired['image'], allowed['artifact']['repository'] + '@{{ .digest }}')
        self.assertEqual(desired['imagePullSecrets'], [{'name': 'harbor-application-pull'}])
        self.assertEqual(value, original)
        secret = next(o for o in objects if o['kind'] == 'ExternalSecret')
        self.assertEqual(secret['spec']['dataFrom'], [{'extract': {'key': 'harbor-cloudlab-public-pull'}}])
        self.assertNotIn('push', json.dumps(objects))
        role = next(o for o in objects if o['kind'] == 'Role')
        self.assertEqual(role['rules'], [{'apiGroups': [''], 'resources': ['secrets'],
            'resourceNames': ['harbor-application-pull'], 'verbs': ['get']}])
        policy = next(o for o in objects if o['kind'] == 'Policy')
        self.assertEqual(policy['spec']['validationFailureAction'], 'Audit')
        self.assertFalse(policy['spec']['background'])
        rules = policy['spec']['rules']
        self.assertIn(value['image'], rules[0]['validate']['foreach'][0]['deny']['conditions']['all'][0]['value'])
        signature = rules[1]['verifyImages'][0]
        self.assertEqual(signature['type'], 'Cosign')
        keyless = signature['attestors'][0]['entries'][0]['keyless']
        self.assertEqual(keyless['subject'], allowed['artifact']['identities'][0])
        self.assertEqual(keyless['issuer'], 'https://token.actions.githubusercontent.com')
        self.assertEqual(keyless['additionalExtensions'], {
            'githubWorkflowRepository': 'example/producer', 'githubWorkflowRef': 'refs/heads/main'})

    def test_private_verification_delivers_only_public_key_and_retains_no_transparency_requirement(self):
        value, allowed = self.inputs()
        allowed['visibility'] = 'private'
        allowed['artifact']['project'] = 'cloudlab-private'
        allowed['artifact']['repository'] = 'registry.example.invalid/cloudlab-private/synthetic'
        objects = self.render(value, allowed)
        secrets = [o for o in objects if o['kind'] == 'ExternalSecret']
        self.assertEqual({o['metadata']['name'] for o in secrets if o['metadata']['namespace'] == allowed['namespace']},
                         {'harbor-application-pull', 'ci-private-verifier'})
        self.assertNotIn('ci-private-signer', json.dumps(objects))
        self.assertNotIn('private_key', json.dumps(objects))
        verifier = next(o for o in secrets if o['metadata']['name'] == 'ci-private-verifier')
        self.assertEqual(verifier['spec']['target']['template']['data'], {'cosign.pub': '{{ .public_key }}'})
        policy = next(o for o in objects if o['kind'] == 'Policy')
        keys = policy['spec']['rules'][1]['verifyImages'][0]['attestors'][0]['entries'][0]['keys']
        self.assertEqual(keys, {'publicKeys': 'k8s://cloudlab-app-synthetic/ci-private-verifier',
                               'rekor': {'ignoreTlog': True}})

    def test_mismatched_projects_paths_repository_and_wildcard_identities_fail(self):
        value, allowed = self.inputs()
        for key, wrong in (('project', 'cloudlab-private'), ('releasePath', 'apps/releases/other.json'),
                           ('repository', 'registry.example.invalid/cloudlab-public/other'),
                           ('identities', ['https://github.com/example/*']), ('action', 'Ignore'),
                           ('sourceRepository', 'other/producer'),
                           ('identities', ['https://github.com/other/platform/.github/workflows/application-publish.yaml@' + 'a' * 40])):
            mutated = copy.deepcopy(allowed)
            mutated['artifact'][key] = wrong
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.render(value, mutated)

    def test_readiness_uses_controller_desired_digest_and_rejects_deployment_or_owner_drift(self):
        from unittest.mock import patch
        from playbooks.services.files.remote import inspect
        value, allowed = self.inputs()
        platform = {'repoURL': 'https://github.com/example/platform.git', 'targetRevision': 'b' * 40}
        digest = 'sha256:' + 'c' * 64
        desired_image = allowed['artifact']['repository'] + '@' + digest
        source = dict(platform, path='charts/service', helm={'valuesObject': dict(value, image=desired_image)})
        application = {'metadata': {'annotations': {'cloudlab.io/artifact-digest': digest,
            'cloudlab.io/source-revision': 'd' * 40, 'cloudlab.io/workflow-run': '123'},
            'ownerReferences': [{'kind': 'ApplicationSet', 'name': allowed['name'], 'controller': True}]},
            'spec': {'project': allowed['name'], 'destination': {'server': 'https://kubernetes.default.svc',
                'namespace': allowed['namespace']}, 'sources': [source, {'repoURL': allowed['repository'],
                'targetRevision': allowed['revision'], 'ref': 'values'}]},
            'status': {'health': {'status': 'Healthy'}, 'sync': {'status': 'Synced'}}}
        deployment = {'metadata': {'generation': 1},
            'status': {'observedGeneration': 1, 'availableReplicas': value['replicas']},
            'spec': {'template': {'spec': {'containers': [{'image': desired_image}]}}}}
        def get(kind, name=None, namespace=None):
            if kind.startswith('application.'):
                return {'spec': {'source': platform}} if name == 'cloudlab-services' else application
            if kind == 'deployment': return deployment
            if kind == 'resourcequota': return {'spec': {'hard': {'requests.cpu': '1'}}}
            raise AssertionError(kind)
        request = {'action': 'backend', 'definition': value, 'approval': allowed}
        with patch('playbooks.services.files.remote.get', side_effect=get):
            inspect(request)
            deployment['spec']['template']['spec']['containers'][0]['image'] = value['image']
            with self.assertRaises(RuntimeError): inspect(request)
            deployment['spec']['template']['spec']['containers'][0]['image'] = desired_image
            application['metadata']['annotations']['cloudlab.io/artifact-digest'] = 'sha256:' + 'e' * 64
            with self.assertRaises(RuntimeError): inspect(request)
            application['metadata']['annotations']['cloudlab.io/artifact-digest'] = digest
            application['metadata']['ownerReferences'] = []
            with self.assertRaises(RuntimeError): inspect(request)

    def test_packaged_notes_keeps_identity_data_and_telemetry_without_runtime_dependency_install(self):
        from playbooks.services.files.examples import definitions
        value = definitions('example.invalid', 'https://github.com/example/platform.git', 'a' * 40,
                            'https://github.com/example/private.git', 'abcdef123456', 'notes', 'notes')['catalog'][0]['definition']
        value['image'] = 'registry.example.invalid/cloudlab-public/notes@sha256:' + 'c' * 64
        payload = {'definition': value, 'issuer': 'https://login.example.invalid/realms/applications',
                   'telemetry': True, 'packaged': True, 'imagePullSecrets': [{'name': 'harbor-application-pull'}]}
        result = subprocess.run(['helm', 'template', 'notes', str(ROOT / 'apps/notes'), '-f', '-'],
                                input=json.dumps(payload), capture_output=True, text=True, timeout=90, check=True)
        objects = [o for o in yaml.safe_load_all(result.stdout) if o]
        self.assertTrue(any(o['kind'] == 'ConfigMap' and o['metadata']['name'] == 'notes-source' for o in objects))
        deployments = [o for o in objects if o['kind'] == 'Deployment']
        self.assertEqual(len(deployments), 2)
        for deployment in deployments:
            pod = deployment['spec']['template']['spec']
            container = pod['containers'][0]
            self.assertEqual(container['image'], value['image'])
            self.assertNotIn('initContainers', pod)
            self.assertNotIn('notes-source', [v['name'] for v in pod['volumes']])
            self.assertEqual(pod['imagePullSecrets'], payload['imagePullSecrets'])
            self.assertEqual(container['command'], ['python', '/app/' + deployment['metadata']['name'].split('-')[-1] + '.py'])
            environment = {v['name']: v['value'] for v in container['env']}
            self.assertEqual(environment['OTEL_ENABLED'], '1')
            self.assertEqual(environment['SOURCE_SHA256'], 'c' * 64)
            self.assertEqual(environment['PYTHONPATH'], '/dependencies:/app:/app/lib.zip')
            if deployment['metadata']['name'] == 'notes-api':
                self.assertEqual({v['name'] for v in pod['volumes']},
                                 {'temporary', 'notes-database', 'notes-objects', 'database-ca'})

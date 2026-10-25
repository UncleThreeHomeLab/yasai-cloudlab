import base64
import copy
import unittest
from unittest.mock import patch

from fixtures import approval, catalog, pull, source_responses
from playbooks.previews.files import contract
from playbooks.previews.files.github import GitHub
from playbooks.previews.files.resources import resources, workload, private_route


class ApprovalTests(unittest.TestCase):
    def test_unique_bounded_browser_origins_and_exact_callbacks(self):
        first, settings = approval(), catalog()
        second = dict(first, instance='b' * 32)
        origins = [contract.hostname(row, settings) for row in (first, second)]
        self.assertNotEqual(*origins)
        for row, host in zip((first, second), origins):
            declaration = contract.client(row, settings)
            self.assertEqual(declaration['callbacks'], ['https://' + host + '/previews/' + row['instance'] + '/callback'])
            from playbooks.keycloak.files.preview_clients import representation
            value = representation(row, settings)
            self.assertEqual(value['webOrigins'], ['https://' + host])
            route = private_route(row, settings, 'state')
            self.assertEqual(route['spec']['hostnames'], [host])
            self.assertEqual(workload(row, settings)['environment']['OIDC_REDIRECT_URI'], declaration['callbacks'][0])
        contract.hostname(first, dict(settings, hostname='a' * 30 + '.internal.example.invalid'))
        for host in ('a' * 31 + '.internal.example.invalid', 'preview.public.example.invalid', '*.internal.example.invalid'):
            with self.assertRaises(ValueError):
                contract.hostname(first, dict(settings, hostname=host))


    def test_historical_rows_remain_structural_but_never_authorize_new_execution(self):
        old = approval()
        with patch.object(contract, 'IMAGE', 'python:3.13-slim-bookworm@sha256:' + 'd' * 64):
            current = copy.deepcopy(old)
            current.update(instance='e' * 32, image=contract.IMAGE)
            settings = catalog([old, current])
            contract.runtime_catalog(settings)
            contract.stored_approval(old)
            with self.assertRaises(ValueError):
                contract.catalog(settings)
            for image in (old['image'], 'evil/public:v1@sha256:' + 'a' * 64):
                row = dict(old, image=image)
                with self.assertRaises(ValueError):
                    contract.approval(row)
                with self.assertRaises(ValueError):
                    contract.client(row, settings)
            self.assertTrue(resources(current, settings, 'https://github.com/example/platform.git', 'state'))
            changed = copy.deepcopy(settings)
            changed['ownership'][contract.names(old)['namespace']] = old['instance'] + ':' + 'f' * 64
            with self.assertRaises(ValueError):
                contract.runtime_catalog(changed)

    def test_exact_blob_not_revision_label_authorizes_source(self):
        row = approval()
        contract.catalog(catalog())
        contract.validate_pull(row, pull())
        contract.verify_blob(row, contract.canonical(row['definition']))
        for change in ('sha', 'fork', 'repository', 'closed', 'draft'):
            value = pull()
            if change == 'sha': value['head']['sha'] = 'd' * 40
            if change == 'fork': value['head']['repo']['fork'] = True
            if change == 'repository': value['head']['repo']['id'] = 124
            if change == 'closed': value['state'] = 'closed'
            if change == 'draft': value['draft'] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                contract.validate_pull(row, value)
        with self.assertRaises(ValueError):
            contract.verify_blob(row, b'{"profile":"synthetic","message":"new commit"}')

    def test_source_cannot_supply_templates_commands_secrets_or_persistence(self):
        for key in ('command', 'initCommand', 'secrets', 'configMaps', 'data', 'persistence', 'exposure', 'chartPath'):
            value = approval()['definition'] | {key: 'untrusted'}
            with self.subTest(key=key), self.assertRaises(ValueError):
                contract.source(contract.canonical(value))
        row = approval()
        row['sourcePath'] = 'previews/../production.json'
        with self.assertRaises(ValueError): contract.approval(row)
        settings = catalog()
        settings['hostname'] = '*.internal.example.invalid'
        with self.assertRaises(ValueError): contract.catalog(settings)

    def test_symlink_and_wrong_blob_size_rejected(self):
        row = approval()
        raw = contract.canonical(row['definition'])
        responses = source_responses(row)
        endpoint = 'repos/' + row['repository'] + '/contents/' + contract.SOURCE_PATH + '?ref=' + row['sourceSha']
        value = responses[endpoint]
        api = GitHub()
        with patch.object(api, 'request', side_effect=lambda path: responses[path]): self.assertEqual(api.blob(row), raw)
        for bad in (value | {'type': 'symlink'}, value | {'target': 'elsewhere'}, value | {'size': len(raw) + 1}):
            changed = responses | {endpoint: bad}
            with patch.object(api, 'request', side_effect=lambda path: changed[path]), self.assertRaises(ValueError): api.blob(row)

    def test_followed_symlink_content_cannot_hide_git_file_mode(self):
        row, api = approval(), GitHub()
        for mode in ('120000', '160000', '100755'):
            responses = source_responses(row, mode)
            with patch.object(api, 'request', side_effect=lambda path: responses[path]) as request, self.assertRaises(ValueError):
                api.blob(row)
            self.assertFalse(any('/contents/' in call.args[0] for call in request.call_args_list))

    def test_fixed_templates_private_route_and_full_selector(self):
        row = approval()
        objects = resources(row, catalog(), 'https://github.com/example/platform.git', 'runtime-uid')
        appset = next(o for o in objects if o['kind'] == 'ApplicationSet')['spec']
        self.assertEqual(appset['generators'][0]['selector']['matchLabels'], {'number': '7', 'head_sha': 'b' * 40})
        self.assertFalse(appset['generators'][0]['pullRequest']['continueOnRepoNotFoundError'])
        self.assertEqual(appset['generators'][0]['pullRequest']['requeueAfterSeconds'], contract.ANONYMOUS_INTERVAL)
        app = appset['template']['spec']
        self.assertEqual(app['source']['targetRevision'], 'c' * 40)
        self.assertEqual(app['source']['path'], 'charts/service')
        self.assertNotIn('valueFiles', app['source']['helm'])
        self.assertEqual(appset['syncPolicy'], {'applicationsSync': 'create-update', 'preserveResourcesOnDeletion': True})
        namespace = objects[0]['metadata']
        self.assertEqual(namespace['labels']['pod-security.kubernetes.io/enforce'], 'restricted')
        self.assertEqual(next(o for o in objects if o['kind'] == 'ResourceQuota')['spec']['hard']['persistentvolumeclaims'], '0')
        self.assertFalse(any(o['kind'] in ('Secret', 'PersistentVolumeClaim', 'ExternalSecret', 'HTTPRoute') for o in objects))

    def test_distinct_audience_and_only_exact_callback_health_exceptions(self):
        first, second = approval(), approval('d' * 32)
        settings = catalog([first, second])
        one, two = contract.client(first, settings), contract.client(second, settings)
        self.assertNotEqual(one['id'], two['id'])
        self.assertNotEqual(one['callbacks'], two['callbacks'])
        self.assertNotIn('*', one['callbacks'][0])
        objects = resources(first, settings, 'https://github.com/example/platform.git', 'runtime-uid')
        policy = next(o for o in objects if o['kind'] == 'AuthorizationPolicy' and o['metadata']['name'] == 'identity')
        self.assertEqual(policy['spec']['rules'][0]['to'][0]['operation']['paths'], ['/healthz', contract.names(first)['path'] + 'callback'])
        self.assertEqual(policy['spec']['rules'][1]['when'][0]['values'], [one['id']])
        self.assertEqual(policy['spec']['rules'][1]['when'][1]['values'], [one['id']])
        l4 = next(o for o in objects if o['kind'] == 'AuthorizationPolicy' and o['metadata']['name'] == 'waypoint-only')
        self.assertEqual(l4['spec']['rules'][0]['from'][0]['source']['principals'], [
            'cluster.local/ns/' + contract.names(first)['namespace'] + '/sa/preview-waypoint'])

    def test_application_artifact_is_approval_bound_without_source_digest_cycle(self):
        row = approval()
        row['definition'] = {'profile': 'application', 'port': 8080, 'healthPath': '/healthz', 'environment': {'PREVIEW_DATA': 'synthetic'},
            'resources': {'requests': {'cpu': '50m', 'memory': '64Mi'}, 'limits': {'cpu': '200m', 'memory': '128Mi'}}}
        row['sourceDigest'] = contract.digest(contract.canonical(row['definition']))
        row['image'] = 'ghcr.io/example/application@sha256:' + '1' * 64
        settings = catalog([row])
        settings['artifacts'] = {'ghcr.io/example/application': {'subject': 'https://github.com/example/platform/.github/workflows/ci.yaml@refs/heads/main',
            'issuer': 'https://token.actions.githubusercontent.com', 'sourceRepository': row['repository'], 'public': True}}
        contract.catalog(settings)
        objects = resources(row, settings, 'https://github.com/example/platform.git', 'runtime-uid')
        verifier = next(o for o in objects if o['kind'] == 'Policy')['spec']['rules'][1]['verifyImages'][0]
        keyless = verifier['attestors'][0]['entries'][0]['keyless']
        self.assertTrue(verifier['required'])
        self.assertEqual(keyless['additionalExtensions']['githubWorkflowSha'], row['sourceSha'])
        self.assertEqual(verifier['imageReferences'], [row['image']])
        self.assertEqual(workload(row, settings)['command'], [])
        mutated = copy.deepcopy(settings)
        mutated['artifacts']['ghcr.io/example/application']['public'] = False
        with self.assertRaises(ValueError): contract.catalog(mutated)

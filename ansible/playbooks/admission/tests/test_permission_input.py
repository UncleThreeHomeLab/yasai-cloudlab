"""Exercise the canonical finite permission validator with the pinned native CEL tool."""
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

from playbooks.admission.files.chart import render, ROOT
from playbooks.data.files.native import render_objects

POLICY = 'cloudlab-permissions-input'
WRITER = 'system:serviceaccount:argocd:argocd-applicationset-controller'
CONTROLLER = 'system:serviceaccount:argocd:argocd-application-controller'


class PermissionInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rendered = render(True)
        cls.policies = [row for row in rendered if row['metadata']['name'] in (POLICY, 'cloudlab-permissions-profiles')]
        cls.policy = next(row for row in cls.policies if row['kind'] == 'ValidatingAdmissionPolicy' and row['metadata']['name'] == POLICY)
        # Native API rejects unknown variable fields before admitting a policy;
        # the CLI does not provide that schema-level integrity guarantee.
        for policy in rendered:
            if policy['kind'] != 'ValidatingAdmissionPolicy':
                continue
            declared = {row['name'] for row in policy['spec'].get('variables', [])}
            for section in ('variables', 'validations', 'matchConditions', 'auditAnnotations'):
                for row in policy['spec'].get(section, []):
                    for key in ('expression', 'messageExpression', 'valueExpression'):
                        references = set(re.findall(r'\bvariables\.([A-Za-z_][A-Za-z_0-9]*)', row.get(key, '')))
                        if references - declared:
                            raise ValueError('Undeclared canonical CEL variables: ' + ', '.join(sorted(references - declared)))
        def files(path):
            chart = ROOT / path
            return {p.relative_to(chart).as_posix(): p.read_bytes() for p in chart.rglob('*') if p.is_file()}
        public = {'permissions': {'enabled': True, 'revision': 'a' * 40, 'acceptanceCommitment': '1' * 64},
            'identity': {'argo': {'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': 'b' * 40}}}
        rows = render_objects(files('gitops/roots/public'), [public])
        cls.parent = next(row for row in rows if row['kind'] == 'ApplicationSet' and row['metadata']['name'] == 'cloudlab-permissions')
        cls.parent['metadata']['uid'] = 'parent'
        cls.projection = render_objects(files('platform/connectivity/permissions'), [{'mode': 'profiles', 'context': {
            'repository': 'https://github.com/UncleThreeHomeLab/yasai-cloudlab.git', 'revision': 'a' * 40, 'commitment': '1' * 64, 'namespace': 'argocd'}}])[0]
        archive = ROOT / 'platform/delivery/argocd/charts/argo-cd-10.9.6.tgz'
        lock = json.loads((ROOT / 'platform/delivery/argocd/artifact.lock.json').read_text())
        if hashlib.sha256(archive.read_bytes()).hexdigest() != lock['chart']['sha256']:
            raise ValueError('Locked Application CRD archive changed')
        rendered = subprocess.run(['helm', 'template', 'argocd', str(archive), '--namespace', 'argocd', '--include-crds'],
            capture_output=True, text=True, timeout=90, check=True)
        cls.crd = next(row for row in yaml.safe_load_all(rendered.stdout) if row and row['kind'] == 'CustomResourceDefinition'
            and row['metadata']['name'] == 'applications.argoproj.io')

    def application(self):
        app = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application', **copy.deepcopy(self.parent['spec']['template'])}
        app['metadata']['annotations']['cloudlab.io/permission-revision'] = 'b' * 40
        app['metadata']['ownerReferences'] = [{'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet',
            'name': 'cloudlab-permissions', 'uid': 'parent', 'controller': True, 'blockOwnerDeletion': True}]
        app['spec']['source']['helm']['valuesObject'] = {'permissions': {'state': 'active', 'assignments': []}}
        return app

    def assignment(self):
        return {'id': 'example', 'profile': 'viewer', 'subject': {'kind': 'User', 'name': 'developer@example.invalid'},
            'scope': {'namespace': 'cloudlab-app-example'}}

    def settled(self, app):
        app['status'] = {'health': {'status': 'Healthy'}, 'sync': {'status': 'Synced', 'revision': 'a' * 40,
            'comparedTo': {'source': copy.deepcopy(app['spec']['source']), 'destination': copy.deepcopy(app['spec']['destination'])}}}
        return app

    def evaluate(self, app, *, old=None, accepted=True, username=WRITER, projection=True, skipped=False, denial=None):
        def literal(value):
            # CEL requires homogeneous aggregate literals; preserve fixture types
            # through dyn at every member without adding runtime JSON extensions.
            if isinstance(value, dict):
                return '{' + ','.join(json.dumps(key) + ':dyn(' + literal(item) + ')' for key, item in value.items()) + '}'
            if isinstance(value, list):
                return '[' + ','.join('dyn(' + literal(item) + ')' for item in value) + ']'
            return json.dumps(value)
        name = 'cloudlab-permissions-profiles' if app['kind'] == 'ConfigMap' else POLICY
        canonical = next(row for row in self.policies if row['kind'] == 'ValidatingAdmissionPolicy' and row['metadata']['name'] == name)
        tested = copy.deepcopy(canonical)
        parameter = copy.deepcopy(self.projection)
        if projection == 'changed':
            parameter['data'].update(revision='c' * 40, commitment='2' * 64)
            parameter['data']['viewer.namespace'] = 'false'
        # The pinned native-VAP CLI hardcodes CREATE and supplies no oldObject.
        # Its fake discovery also reports ConfigMaps as cluster-scoped, so native
        # param collection errors become an empty/excluded engine response. Bind
        # params and request context reversibly for expression-only checks. Actual
        # dispatch, namespace and missing-param behavior need native qualification.
        for section in ('variables', 'validations', 'matchConditions'):
            for row in tested['spec'].get(section, []):
                row['expression'] = re.sub(r'\brequest\.operation\b', 'variables.fixtureOperation', row['expression'])
                if name == POLICY:
                    row['expression'] = re.sub(r'\bparams\b', 'variables.fixtureParams', row['expression'])
                if old is not None:
                    row['expression'] = re.sub(r'\boldObject\b', 'variables.previousFixture', row['expression'])
        if name == POLICY:
            tested['spec'].pop('paramKind')
            tested['spec']['variables'].insert(0, {'name': 'fixtureParams', 'expression': literal(parameter)})
        tested['spec'].setdefault('variables', []).insert(0, {'name': 'fixtureOperation',
            'expression': json.dumps('CREATE' if old is None else 'UPDATE')})
        if old is not None:
            tested['spec']['variables'].insert(0, {'name': 'previousFixture', 'expression': literal(old)})
        restored = copy.deepcopy(tested)
        restored['spec']['variables'] = [row for row in restored['spec']['variables']
            if row['name'] not in ('fixtureOperation', 'previousFixture', 'fixtureParams')]
        for section in ('variables', 'validations', 'matchConditions'):
            for row in restored['spec'].get(section, []):
                row['expression'] = row['expression'].replace('variables.fixtureOperation', 'request.operation').replace('variables.previousFixture', 'oldObject')
                row['expression'] = row['expression'].replace('variables.fixtureParams', 'params')
        if name == POLICY:
            restored['spec']['paramKind'] = copy.deepcopy(canonical['spec']['paramKind'])
        if 'variables' not in canonical['spec']: restored['spec'].pop('variables')
        self.assertEqual(restored, canonical)
        binding = next(row for row in self.policies if row['kind'] == 'ValidatingAdmissionPolicyBinding' and row['metadata']['name'] == name)
        tested_binding = copy.deepcopy(binding)
        if name == POLICY:
            original_ref = tested_binding['spec'].pop('paramRef')
            self.assertEqual(tested_binding | {'spec': tested_binding['spec'] | {'paramRef': original_ref}}, binding)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            contents = {'policy.yaml': [tested, tested_binding], 'application.yaml': app,
                'application-crd.yaml': self.crd,
                'cluster.yaml': {'apiVersion': 'cli.kyverno.io/v1alpha1', 'kind': 'ClusterResource',
                    'metadata': {'name': 'permissions'}, 'spec': {'crds': ['application-crd.yaml'],
                        'resources': [{'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'argocd'}}]}},
                'parameters.yaml': parameter if projection else [],
                'values.yaml': {'apiVersion': 'cli.kyverno.io/v1alpha1', 'kind': 'Values', 'globalValues': {
                    'request.operation': 'CREATE' if old is None else 'UPDATE'}},
                'user.yaml': {'apiVersion': 'cli.kyverno.io/v1alpha1', 'kind': 'UserInfo', 'metadata': {'name': 'writer'},
                    'userInfo': {'username': username}},
                'kyverno-test.yaml': {'apiVersion': 'cli.kyverno.io/v1alpha1', 'kind': 'Test', 'metadata': {'name': 'permissions'},
                    'policies': ['policy.yaml'], 'resources': ['application.yaml'], 'variables': 'values.yaml',
                    'paramResources': [],
                    'clusterResources': ['cluster.yaml'],
                    'userinfo': 'user.yaml', 'results': [{'isValidatingAdmissionPolicy': True,
                        'kind': app['kind'], 'policy': name, 'resources': [app['metadata']['name']],
                        'operation': 'CREATE' if old is None else 'UPDATE',
                        'result': 'skip' if skipped else 'pass' if accepted else 'fail'}]}}
            for filename, value in contents.items():
                (path / filename).write_text(yaml.safe_dump_all(value) if isinstance(value, list) else yaml.safe_dump(value))
            result = subprocess.run(['kyverno', 'test', str(path), '--detailed-results', '--remove-color', '--v=2'], capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('error)', result.stdout)
        self.assertNotIn('ERR', result.stderr, result.stderr)
        if not skipped:
            self.assertNotIn('Excluded', result.stdout, result.stdout)
            if not accepted:
                self.assertTrue(any(row['message'] in result.stdout for row in canonical['spec']['validations']), result.stdout)
                if denial:
                    self.assertIn(denial, result.stdout)

    def test_empty_creation_then_converged_exact_subject_grant(self):
        app = self.application()
        self.evaluate(app)
        old = self.settled(copy.deepcopy(app))
        app = copy.deepcopy(old)
        app['spec']['source']['helm']['valuesObject']['permissions']['assignments'] = [self.assignment()]
        self.evaluate(app, old=old)
        self.evaluate(app, accepted=False)

    def test_catalog_promotion_must_converge_before_new_ids(self):
        old = self.settled(self.application())
        addition = copy.deepcopy(old)
        addition['spec']['source']['helm']['valuesObject']['permissions']['assignments'] = [self.assignment()]
        self.evaluate(addition, old=old)
        promoted = copy.deepcopy(old)
        promoted['spec']['source']['targetRevision'] = 'c' * 40
        promoted['metadata']['annotations']['cloudlab.io/permission-public-revision'] = 'c' * 40
        with patch.dict(self.projection['data'], revision='c' * 40):
            self.evaluate(promoted, old=old)
            promoted['spec']['source']['helm']['valuesObject']['permissions']['assignments'] = [self.assignment()]
            self.evaluate(promoted, old=old, accepted=False, denial='already converged catalog pin')

    def test_invalid_private_inputs_are_rejected_before_stored_spec_changes(self):
        old = self.settled(self.application())
        cases = [None, {'state': 'active', 'assignments': [], 'unexpected': True},
            {'state': 'retired', 'assignments': [self.assignment()]},
            {'state': 'active', 'assignments': [self.assignment(), self.assignment()]},
            {'state': 'active', 'assignments': [self.assignment() | {'id': 'reader-' + str(i)} for i in range(129)]}]
        for change in ({'profile': 'missing'}, {'subject': {'kind': 'Group', 'name': 'developers'}},
                {'subject': {'kind': 'User', 'name': 'system:admin'}}, {'scope': {'cluster': False}},
                {'scope': {'cluster': True}}, {'scope': {'namespace': 'example', 'cluster': True}},
                {'scope': {'namespace': 'Example'}}, {'id': 'bad id'}, {'extra': True}):
            cases.append({'state': 'active', 'assignments': [self.assignment() | change]})
        for value in cases:
            app = copy.deepcopy(old)
            app['spec']['source']['helm']['valuesObject']['permissions'] = value
            with self.subTest(value=value): self.evaluate(app, old=old, accepted=False, denial='bounded subject, profile, scope or retirement contract')

    def test_old_valid_spec_survives_changed_parameters_but_controls_are_always_checked(self):
        old = self.application()
        self.evaluate(old, old=copy.deepcopy(old), username=CONTROLLER, projection='changed')
        for change in ({'argocd.argoproj.io/skip-reconcile': 'false'}, {'argocd.argoproj.io/sync-wave': '100'}):
            app = copy.deepcopy(old)
            app['metadata']['annotations'].update(change)
            self.evaluate(app, old=old, username=CONTROLLER, projection=True, accepted=False)

    def test_missing_parameters_never_select_unrelated_applications(self):
        self.assertEqual(self.policy['spec']['matchConstraints']['resourceRules'][0]['resourceNames'], ['cloudlab-permissions'])
        binding = next(row for row in self.policies if row['kind'] == 'ValidatingAdmissionPolicyBinding' and row['metadata']['name'] == POLICY)
        self.assertEqual(binding['spec']['paramRef'], {'name': 'cloudlab-permissions-profiles', 'namespace': 'argocd', 'parameterNotFoundAction': 'Deny'})
        # Missing native parameters are covered by the actual API proof, not the
        # CLI's broken fake discovery. These cases only check expression exclusion.
        unrelated = self.application()
        unrelated['metadata']['name'] = 'cloudlab-unrelated'
        self.evaluate(unrelated, projection=False, skipped=True)
        self.evaluate(unrelated, old=copy.deepcopy(unrelated), projection=False, skipped=True)

    def test_reused_ids_require_complete_current_source_and_no_active_operation(self):
        old = self.settled(self.application())
        app = copy.deepcopy(old)
        app['spec']['source']['helm']['valuesObject']['permissions']['assignments'] = [self.assignment()]
        for phase in ('Running', 'Terminating'):
            unsettled = copy.deepcopy(old)
            unsettled['status']['operationState'] = {'phase': phase}
            proposed = copy.deepcopy(app)
            proposed['status'] = copy.deepcopy(unsettled['status'])
            self.evaluate(proposed, old=unsettled, accepted=False, denial='New or reused assignment IDs')
        stale = copy.deepcopy(old)
        stale['status']['sync']['comparedTo']['source']['helm']['valuesObject']['permissions']['state'] = 'retired'
        app['status'] = copy.deepcopy(stale['status'])
        self.evaluate(app, old=stale, accepted=False, denial='New or reused assignment IDs')
        stale = copy.deepcopy(old)
        stale['status']['sync']['comparedTo']['destination']['namespace'] = 'foreign'
        app['status'] = copy.deepcopy(stale['status'])
        self.evaluate(app, old=stale, accepted=False, denial='New or reused assignment IDs')

    def test_service_account_and_cluster_profiles_remain_explicit(self):
        old = self.settled(self.application())
        for assignment in (self.assignment() | {'subject': {'kind': 'ServiceAccount', 'name': 'reader', 'namespace': 'example'}},
                self.assignment() | {'profile': 'platform-engineer', 'scope': {'cluster': True}}):
            app = copy.deepcopy(old)
            app['spec']['source']['helm']['valuesObject']['permissions']['assignments'] = [assignment]
            self.evaluate(app, old=old)

    def test_operations_carry_over_but_overrides_and_unsafe_options_are_denied(self):
        settled = self.settled(self.application())
        settled['status']['operationState'] = {'phase': 'Succeeded'}
        old = copy.deepcopy(settled)
        old['status'].pop('operationState')
        # Argo v3.5.3 SelfHealAttemptsCount uses JSON autoHealAttemptsCount.
        old['operation'] = {'sync': {'revision': 'a' * 40, 'source': copy.deepcopy(old['spec']['source']), 'prune': True,
            'syncOptions': copy.deepcopy(old['spec']['syncPolicy']['syncOptions']), 'autoHealAttemptsCount': 1,
            'resources': [{'group': 'rbac.authorization.k8s.io', 'kind': 'RoleBinding', 'name': 'synthetic-binding'}]},
            'initiatedBy': {'automated': True}, 'retry': copy.deepcopy(old['spec']['syncPolicy']['retry'])}
        self.evaluate(old, old=settled, username=CONTROLLER)
        misspelled = copy.deepcopy(old)
        misspelled['operation']['sync']['selfHealAttemptsCount'] = misspelled['operation']['sync'].pop('autoHealAttemptsCount')
        self.evaluate(misspelled, old=settled, username=CONTROLLER, accepted=False, denial='Permission operations cannot override')
        app = copy.deepcopy(old)
        app['spec']['source']['helm']['valuesObject']['permissions']['state'] = 'retired'
        self.evaluate(app, old=old)
        self.evaluate(app, old=copy.deepcopy(app), username=CONTROLLER, projection=True)
        for sync in ({'revision': 'b' * 40}, {'manifests': ['arbitrary']}, {'syncOptions': []}, {'syncOptions': ['Force=true']},
                {'syncStrategy': {'apply': {'force': True}}}):
            bad = copy.deepcopy(app)
            bad['operation'] = {'sync': sync}
            self.evaluate(bad, old=app, username=CONTROLLER, accepted=False, denial='Permission operations cannot override')
        manual = copy.deepcopy(app)
        manual['operation']['sync']['source'] = copy.deepcopy(manual['spec']['source'])
        self.evaluate(manual, old=app, username='system:serviceaccount:argocd:argocd-server', accepted=False,
            denial='Permission operations cannot override')
        cleared = copy.deepcopy(app)
        cleared.pop('operation')
        self.evaluate(cleared, old=app, username=CONTROLLER, projection=True)
        self.evaluate(manual, old=cleared, username='system:serviceaccount:argocd:argocd-server', projection=True)

    def test_foreign_writer_source_channels_and_tuple_changes_are_denied(self):
        old = self.settled(self.application())
        app = copy.deepcopy(old)
        app['spec']['source']['helm']['valuesObject']['permissions']['assignments'] = [self.assignment()]
        self.evaluate(app, old=old, username='developer', accepted=False)
        for field, value in (('values', 'permissions: {}'), ('valueFiles', ['override.yaml']),
                ('parameters', [{'name': 'mode', 'value': 'profiles'}])):
            bad = copy.deepcopy(app)
            bad['spec']['source']['helm'][field] = value
            self.evaluate(bad, old=old, accepted=False)
        before = self.settled(copy.deepcopy(app))
        app['spec']['source']['helm']['valuesObject']['permissions']['assignments'][0]['subject']['name'] = 'other'
        self.evaluate(app, old=before, accepted=False, denial='Remove an assignment')

    def test_profile_projection_has_one_public_owner_and_no_implicit_adoption(self):
        profile = copy.deepcopy(self.projection)
        profile['metadata']['annotations'] = {'argocd.argoproj.io/tracking-id':
            'cloudlab-permissions-profiles:/ConfigMap:argocd/cloudlab-permissions-profiles'}
        self.evaluate(profile, username=CONTROLLER, projection=False)
        self.evaluate(profile, username=WRITER, accepted=False)
        foreign = copy.deepcopy(profile)
        foreign['metadata']['labels']['cloudlab.io/owner'] = 'other'
        self.evaluate(profile, old=foreign, username=CONTROLLER, accepted=False)

    def test_create_status_accepts_only_empty_or_exact_native_zero_evidence(self):
        zero = {'sync': {'status': '', 'comparedTo': {'source': {'repoURL': ''}, 'destination': {}}},
            'health': {}, 'summary': {}, 'sourceHydrator': {}}
        for status, accepted in (({}, True), (zero, True), ({'sync': {'status': 'Synced'}}, False)):
            app = self.application()
            app['status'] = status
            self.evaluate(app, accepted=accepted)

    def test_only_controller_writes_convergence_or_clears_existing_operations(self):
        old = self.application()
        forged = self.settled(copy.deepcopy(old))
        for username in (WRITER, 'developer', 'system:serviceaccount:argocd:argocd-server', CONTROLLER):
            self.evaluate(forged, old=old, username=username, accepted=username == CONTROLLER)
        old['operation'] = {'sync': {'revision': 'a' * 40, 'source': copy.deepcopy(old['spec']['source']),
            'syncOptions': copy.deepcopy(old['spec']['syncPolicy']['syncOptions'])}}
        cleared = copy.deepcopy(old)
        cleared.pop('operation')
        for username in (WRITER, 'developer', 'system:serviceaccount:argocd:argocd-server', CONTROLLER):
            self.evaluate(cleared, old=old, username=username, accepted=username == CONTROLLER)

    def test_server_operation_start_and_termination_preserve_other_status(self):
        server = 'system:serviceaccount:argocd:argocd-server'
        old = self.settled(self.application())
        old['status']['operationState'] = {'phase': 'Failed', 'retryCount': 1, 'message': 'previous'}
        started = copy.deepcopy(old)
        started['status'].pop('operationState')
        started['operation'] = {'sync': {'revision': 'a' * 40, 'source': copy.deepcopy(started['spec']['source']),
            'syncOptions': copy.deepcopy(started['spec']['syncPolicy']['syncOptions'])}}
        self.evaluate(started, old=old, username=server)
        forged = copy.deepcopy(started)
        forged['status']['sync']['comparedTo']['source']['helm']['valuesObject']['permissions']['state'] = 'retired'
        self.evaluate(forged, old=old, username=server, accepted=False)
        running = copy.deepcopy(started)
        running['status']['operationState'] = {'phase': 'Running', 'retryCount': 0, 'message': 'current'}
        terminating = copy.deepcopy(running)
        terminating['status']['operationState']['phase'] = 'Terminating'
        self.evaluate(terminating, old=running, username=server)
        forged = copy.deepcopy(terminating)
        forged['status']['operationState']['retryCount'] = 9
        self.evaluate(forged, old=running, username=server, accepted=False)
        replaced = copy.deepcopy(running)
        replaced['operation']['sync']['prune'] = False
        self.evaluate(replaced, old=running, username=server, accepted=False)

    def test_parent_identity_and_provenance_cannot_be_changed_by_metadata_actors(self):
        old = self.application()
        for case in ('owner', 'commitment', 'version'):
            app = copy.deepcopy(old)
            if case == 'owner': app['metadata']['ownerReferences'][0]['uid'] = 'foreign'
            if case == 'commitment': app['metadata']['annotations']['cloudlab.io/permission-commitment'] = '2' * 64
            if case == 'version': app['metadata']['annotations']['cloudlab.io/permission-input-version'] = 'untrusted'
            with self.subTest(case=case): self.evaluate(app, old=old, username=CONTROLLER, accepted=False)

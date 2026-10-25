"""Qualify native admission separately from the controller's unprivileged RBAC."""
import copy
import json
import subprocess

from playbooks.previews.files.contract import catalog

CONTROLLER = 'system:serviceaccount:argocd:cloudlab-previews'
POLICIES = ('namespaces', 'rolebindings', 'objects')


def native(get, settings, namespace_object=None):
    catalog(settings)
    for suffix in POLICIES:
        name = 'cloudlab-preview-' + suffix
        policy = get('validatingadmissionpolicy', name)
        binding = get('validatingadmissionpolicybinding', name)
        if (not policy or policy['spec'].get('failurePolicy') != 'Fail' or 'paramKind' in policy['spec'] or
                policy.get('status', {}).get('observedGeneration') != policy['metadata']['generation'] or
                policy.get('status', {}).get('typeChecking', {}).get('expressionWarnings') or
                not binding or binding['spec'].get('policyName') != name or
                binding['spec'].get('validationActions') != ['Deny'] or
                'paramRef' in binding['spec']):
            raise RuntimeError('Preview admission is not compiled with its fail-closed binding')
        authorization = [row['expression'] for row in policy['spec'].get('variables', []) if row['name'] == 'authorization']
        if len(authorization) != 1 or json.loads(authorization[0]) != settings['ownership']:
            raise RuntimeError('Preview admission administrator authorization differs from its catalog')
    def request(arguments, obj=None, denied_by=None):
        result = subprocess.run(['/usr/local/bin/k3s', 'kubectl', '--as=' + CONTROLLER,
            '--as-group=system:masters', *arguments], input=json.dumps(obj) if obj is not None else None,
            capture_output=True, text=True, timeout=30)
        if denied_by is None:
            if result.returncode:
                raise RuntimeError('Native positive preview admission probe failed')
        elif not result.returncode or 'cloudlab-preview-' + denied_by not in result.stderr:
            raise RuntimeError('Native preview rejection was not established by the required admission policy')
    bad = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'cloudlab-app-preview-admission-probe'}}
    request(['create', '--dry-run=server', '-f', '-'], bad, 'namespaces')
    # A privileged impersonation group isolates admission from RBAC. Nothing persists.
    request(['delete', 'namespace', 'argocd', '--dry-run=server', '--wait=false'], denied_by='namespaces')
    bad_binding = {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'RoleBinding',
        'metadata': {'name': 'preview-admission-probe', 'namespace': 'argocd'},
        'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': 'cluster-admin'},
        'subjects': [{'kind': 'ServiceAccount', 'name': 'cloudlab-previews', 'namespace': 'argocd'}]}
    request(['create', '--dry-run=server', '-f', '-'], bad_binding, 'rolebindings')
    bad_input = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'preview-admission-probe', 'namespace': 'argocd'}, 'data': {}}
    request(['create', '--dry-run=server', '-f', '-'], bad_input, 'objects')
    positives = 0
    if namespace_object is not None:
        request(['create', '--dry-run=server', '-f', '-'], namespace_object)
        positives += 1
        invalid = copy.deepcopy(namespace_object)
        invalid['metadata']['labels']['pod-security.kubernetes.io/enforce'] = 'privileged'
        request(['create', '--dry-run=server', '-f', '-'], invalid, 'namespaces')
    return {'native_policy_rejections': 4 + positives, 'native_positive_namespace': positives,
            'persistent_mutations': 0, 'admission_isolated_from_rbac': True}

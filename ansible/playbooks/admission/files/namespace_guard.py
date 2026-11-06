"""Qualify the declared native Namespace guard without creating resources."""
import copy
from pathlib import Path

NAMESPACE_GUARD_NAME = 'cloudlab-workload-namespace-native'


def namespace_guard_desired(declaration=None):
    if declaration is None:
        import yaml
        declaration = yaml.safe_load((Path(__file__).resolve().parents[4] /
            'platform/delivery/admission/policies/templates/workload-namespace.yaml').read_text())
    if (not isinstance(declaration, dict) or declaration.get('kind') != 'ValidatingPolicy' or
            declaration.get('metadata', {}).get('name') != 'cloudlab-workload-namespace' or
            declaration.get('spec', {}).get('failurePolicy') != 'Fail' or
            declaration['spec'].get('validationActions') != ['Deny'] or
            not declaration['spec'].get('variables') or not declaration['spec'].get('validations')):
        raise RuntimeError('Native namespace guard requires its complete declared Namespace contract')
    policy = {'apiVersion': 'admissionregistration.k8s.io/v1', 'kind': 'ValidatingAdmissionPolicy',
        'metadata': {'name': NAMESPACE_GUARD_NAME, 'annotations': {
            'argocd.argoproj.io/sync-wave': '1',
            'argocd.argoproj.io/sync-options': 'ServerSideApply=true,Prune=false,Delete=false'}},
        'spec': {'failurePolicy': 'Fail', 'matchConstraints': {
            'matchPolicy': 'Exact', 'namespaceSelector': {}, 'objectSelector': {}, 'resourceRules': [{
                'apiGroups': [''], 'apiVersions': ['v1'], 'operations': ['CREATE', 'UPDATE'],
                'resources': ['namespaces'], 'scope': 'Cluster'}]},
            'variables': copy.deepcopy(declaration['spec']['variables']),
            'validations': copy.deepcopy(declaration['spec']['validations'])}}
    binding = {'apiVersion': 'admissionregistration.k8s.io/v1', 'kind': 'ValidatingAdmissionPolicyBinding',
        'metadata': {'name': NAMESPACE_GUARD_NAME, 'annotations': {
            'argocd.argoproj.io/sync-wave': '2',
            'argocd.argoproj.io/sync-options': 'ServerSideApply=true,Prune=false,Delete=false'}},
        'spec': {'policyName': NAMESPACE_GUARD_NAME, 'validationActions': ['Deny']}}
    return [policy, binding]


def namespace_guard_validate(documents, declaration=None):
    expected = namespace_guard_desired(declaration)
    if not isinstance(documents, list) or len(documents) != 2:
        raise RuntimeError('Native namespace guard requires its complete policy and binding')
    for actual, reference in zip(documents, expected, strict=True):
        kind = reference['kind']
        marker = 'cloudlab-workload-policy:admissionregistration.k8s.io/' + kind + ':cloudlab-policy/' + NAMESPACE_GUARD_NAME
        if (not isinstance(actual, dict) or actual.get('apiVersion') != reference['apiVersion'] or
                actual.get('kind') != kind or actual.get('metadata', {}).get('name') != NAMESPACE_GUARD_NAME or
                actual.get('spec') != reference['spec'] or
                any(actual.get('metadata', {}).get('annotations', {}).get(key) != value
                    for key, value in reference['metadata']['annotations'].items()) or
                actual.get('metadata', {}).get('annotations', {}).get('argocd.argoproj.io/tracking-id') != marker):
            raise RuntimeError('Native namespace guard differs from its exact declared owner and scope')
        if kind == 'ValidatingAdmissionPolicy':
            status = actual.get('status', {})
            typing = status.get('typeChecking', {})
            if (not actual['metadata'].get('generation') or status.get('observedGeneration') != actual['metadata']['generation'] or
                    not isinstance(typing, dict) or typing.get('expressionWarnings') or
                    any(row.get('status') == 'False' for row in status.get('conditions', []))):
                raise RuntimeError('Native namespace guard type-checking is incomplete or has warnings')
    return True


def namespace_guard_denied(diagnostics, message):
    attribution = "ValidatingAdmissionPolicy '" + NAMESPACE_GUARD_NAME + "' with binding '" + NAMESPACE_GUARD_NAME + "' denied request:"
    return attribution in diagnostics and message in diagnostics


def authority(documents):
    result = []
    for obj in documents:
        meta = obj.get('metadata', {})
        if (not isinstance(meta.get('uid'), str) or not meta['uid'] or
                type(meta.get('generation')) is not int or meta['generation'] < 1 or
                meta.get('deletionTimestamp') or meta.get('ownerReferences') or meta.get('finalizers')):
            raise RuntimeError('Native namespace guard has no stable non-deleting owner')
        result.append({'uid': meta['uid'], 'generation': meta['generation'],
            'annotations': copy.deepcopy(meta.get('annotations', {})),
            'labels': copy.deepcopy(meta.get('labels', {})), 'spec': copy.deepcopy(obj['spec'])})
    return result


def qualify(declaration, read, probe, previous=None):
    """Fence exact declared ownership around positive and negative server dry-runs."""
    desired = namespace_guard_desired(declaration)
    def observe():
        documents = [read(kind, NAMESPACE_GUARD_NAME) or {} for kind in (
            'validatingadmissionpolicy.admissionregistration.k8s.io',
            'validatingadmissionpolicybinding.admissionregistration.k8s.io')]
        namespace_guard_validate(documents, declaration)
        return authority(documents)
    before = observe()
    if previous is not None and previous != before:
        raise RuntimeError('Native namespace guard authority changed during service activation')
    name = 'cloudlab-app-native-guard-probe'
    if read('namespace', name):
        raise RuntimeError('Native namespace guard qualification requires its unused synthetic name')
    def dry_run(document):
        result = probe(document)
        if (not isinstance(result, tuple) or len(result) != 2 or type(result[0]) is not int or
                not isinstance(result[1], str)):
            raise RuntimeError('Native namespace guard requires a typed server dry-run result')
        return result
    good = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': name, 'labels': {
        'cloudlab.io/owner': 'service-platform', 'istio.io/dataplane-mode': 'ambient',
        'cloudlab.io/service-secrets': 'approved', 'pod-security.kubernetes.io/enforce': 'restricted',
        'pod-security.kubernetes.io/enforce-version': 'v1.36'}}}
    if dry_run(good)[0]:
        raise RuntimeError('Native namespace guard positive control was not admitted')
    bad = copy.deepcopy(good)
    bad['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
    code, diagnostics = dry_run(bad)
    if not code or not namespace_guard_denied(diagnostics, desired[0]['spec']['validations'][0]['message']):
        raise RuntimeError('Native namespace guard did not deny its service activation CREATE probe')
    if before != observe():
        raise RuntimeError('Native namespace guard changed during service activation probes')
    return before

"""Continuous bounded preview lifecycle, independent of Git generator deletion."""
import copy
import json
import time
from pathlib import Path

try:
    from .contract import OWNER, APPROVALS, STATE, IDENTITY_STATE, MAX_ACTIVE, ANONYMOUS_INTERVAL, catalog, canonical, digest, names, validate_pull, verify_blob
    from .github import GitHub
    from .kube import Kubernetes, APIError, identity
    from .lifecycle import enroll, retirement, owned, namespace_disposable
    from .resources import resources, workload_keys, private_route
except ImportError:
    from contract import OWNER, APPROVALS, STATE, IDENTITY_STATE, MAX_ACTIVE, ANONYMOUS_INTERVAL, catalog, canonical, digest, names, validate_pull, verify_blob
    from github import GitHub
    from kube import Kubernetes, APIError, identity
    from lifecycle import enroll, retirement, owned, namespace_disposable
    from resources import resources, workload_keys, private_route


def contains(observed, expected):
    if isinstance(expected, dict):
        return isinstance(observed, dict) and all(key in observed and contains(observed[key], value) for key, value in expected.items())
    if isinstance(expected, list):
        return isinstance(observed, list) and len(observed) == len(expected) and all(contains(a, b) for a, b in zip(observed, expected))
    return observed == expected


class Controller:
    def __init__(self, kube, github, now):
        self.kube, self.github, self.now = kube, github, now
        self.object = kube.get(('v1', 'ConfigMap', 'argocd', STATE))
        if self.object is None:
            self.object = kube.create({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {
                'name': STATE, 'namespace': 'argocd', 'labels': {'cloudlab.io/owner': OWNER}},
                'data': {'state.json': json.dumps({'format': 1, 'entries': {}})}})
        meta = self.object['metadata']
        if (meta.get('labels', {}).get('cloudlab.io/owner') != OWNER or not meta.get('uid') or
                meta.get('ownerReferences') or meta.get('finalizers')):
            raise ValueError('Preview runtime state has conflicting ownership')
        self.state = json.loads(self.object['data']['state.json'])
        if (set(self.state) - {'format', 'entries', 'settings', 'checks', 'providerCheckAt'} or self.state.get('format') != 1 or
                not isinstance(self.state.get('entries'), dict) or len(self.state['entries']) > 256):
            raise ValueError('Preview runtime state is invalid')

    def save(self):
        obj = copy.deepcopy(self.object)
        obj['data'] = {'state.json': json.dumps(self.state, sort_keys=True)}
        if obj['data'] != self.object['data']:
            self.object = self.kube.replace(obj)

    def materialize(self, record, desired):
        row = record['approval']
        key = identity(desired)
        receipt = next((r for r in record['resources'] if r['key'] == list(key)), None)
        if receipt is None:
            receipt = {'key': list(key), 'desiredDigest': digest(canonical(desired)), 'uid': None}
            record['resources'].append(receipt)
            self.save()
        if receipt['desiredDigest'] != digest(canonical(desired)):
            raise ValueError('Preview resource declaration changed within one instance')
        if receipt.get('collision'):
            raise ValueError('Preexisting preview resource collision requires administrator review')
        if desired['kind'] == 'RoleBinding' and receipt['uid'] is None:
            attempted = receipt.get('creationAttempted', False)
            receipt['creationAttempted'] = True
            self.save()
            try:
                observed = self.kube.create(desired)
            except APIError as error:
                if error.code != 409:
                    raise
                if not attempted:
                    receipt['collision'] = True
                    self.save()
                    raise ValueError('Preexisting preview inventory binding cannot be adopted') from None
                observed = self.kube.get(key)
        else:
            observed = self.kube.get(key)
            if observed is not None and receipt['uid'] is None and not receipt.get('creationAttempted'):
                receipt['collision'] = True
                self.save()
                raise ValueError('Preexisting preview resource cannot be adopted')
        if observed is None:
            if receipt['uid'] is not None:
                raise ValueError('Preview resource disappeared; implicit replacement refused')
            receipt['creationAttempted'] = True
            self.save()
            observed = self.kube.create(desired)
        owned(observed, row, self.object['metadata']['uid'], receipt['uid'])
        # A crash after POST may resume only its pre-recorded complete declaration.
        if receipt['uid'] is None:
            for field in ('spec', 'data', 'rules', 'roleRef', 'subjects'):
                if field in desired and not contains(observed.get(field), desired[field]):
                    raise ValueError('Interrupted preview creation differs from recorded declaration')
            receipt['uid'] = observed['metadata']['uid']
            self.save()
        elif any(field in desired and not contains(observed.get(field), desired[field]) for field in ('spec', 'data', 'rules', 'roleRef', 'subjects')):
            if desired['kind'] == 'Namespace':
                raise ValueError('Preview namespace drift requires administrator review')
            replacement = copy.deepcopy(desired)
            replacement['metadata'].update({key: observed['metadata'][key] for key in ('uid', 'resourceVersion')})
            observed = self.kube.replace(replacement)
        return observed

    def waypoint_ready(self, row):
        namespace = names(row)['namespace']
        gateway = self.kube.get(('gateway.networking.k8s.io/v1', 'Gateway', namespace, 'preview-waypoint'))
        if not gateway or any(not any(condition.get('type') == kind and condition.get('status') == 'True' and
                condition.get('observedGeneration') == gateway['metadata'].get('generation')
                for condition in gateway.get('status', {}).get('conditions', [])) for kind in ('Accepted', 'Programmed')):
            return False
        proxy = json.loads(Path(__file__).with_name('images.lock.json').read_text())['proxyv2']
        for kind, version in (('Deployment', 'apps/v1'), ('Service', 'v1'), ('ServiceAccount', 'v1')):
            obj = self.kube.get((version, kind, namespace, 'preview-waypoint'))
            if not obj or not any(ref.get('uid') == gateway['metadata']['uid'] and ref.get('kind') == 'Gateway' and
                    ref.get('name') == 'preview-waypoint' and ref.get('apiVersion') == 'gateway.networking.k8s.io/v1'
                    for ref in obj['metadata'].get('ownerReferences', [])):
                return False
            if kind == 'Deployment':
                containers = obj['spec']['template']['spec']['containers']
                if (len(containers) != 1 or containers[0]['image'] != proxy or obj['spec']['replicas'] != 1 or
                        containers[0]['resources'] != {'requests': {'cpu': '50m', 'memory': '128Mi'}, 'limits': {'cpu': '250m', 'memory': '256Mi'}} or
                        obj.get('status', {}).get('observedGeneration') != obj['metadata']['generation'] or
                        obj.get('status', {}).get('readyReplicas') != 1):
                    return False
        return True

    def publication_ready(self, row, settings):
        n = names(row)
        service = self.kube.get(('v1', 'Service', n['namespace'], 'preview'))
        app = self.kube.get(('argoproj.io/v1alpha1', 'Application', 'argocd', n['name']))
        if (not service or service['metadata'].get('labels', {}).get('istio.io/use-waypoint') != 'preview-waypoint' or
                service['metadata']['labels'].get('istio.io/ingress-use-waypoint') != 'true' or
                not app or app.get('status', {}).get('sync', {}).get('status') != 'Synced' or
                app.get('status', {}).get('sync', {}).get('revision') != row['platformRevision'] or
                app.get('status', {}).get('health', {}).get('status') != 'Healthy'):
            return False
        self.materialize(self.state['entries'][row['instance']], private_route(row, settings, self.object['metadata']['uid']))
        import urllib.request
        import urllib.error
        try:
            with urllib.request.urlopen('https://' + settings['hostname'] + n['path'], timeout=10):
                raise ValueError('Preview ingress accepted an unauthenticated application request')
        except urllib.error.HTTPError as error:
            if error.code not in (401, 403):
                return False
        return True

    def capture_workloads(self, record):
        row, n = record['approval'], names(record['approval'])
        app = self.kube.get(('argoproj.io/v1alpha1', 'Application', 'argocd', n['name']))
        if app:
            owned(app, row, self.object['metadata']['uid'])
            appset = next((r for r in record['resources'] if r['key'][1] == 'ApplicationSet'), None)
            if not appset or app.get('metadata', {}).get('ownerReferences') != [{
                    'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet', 'name': n['name'],
                    'uid': appset['uid'], 'controller': True, 'blockOwnerDeletion': True}]:
                raise ValueError('Generated preview Application has an unexpected owner')
            self.capture(record, app)
        for key in workload_keys(row):
            obj = self.kube.get(key)
            if obj:
                owned(obj, row, self.object['metadata']['uid'])
                annotation = obj['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '')
                if not annotation.startswith(n['name'] + ':') or obj['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER:
                    raise ValueError('Preview workload has conflicting GitOps ownership')
                self.capture(record, obj)

    def capture(self, record, obj):
        key = list(identity(obj))
        receipt = next((r for r in record['resources'] if r['key'] == key), None)
        if receipt and receipt['uid'] != obj['metadata']['uid']:
            raise ValueError('Preview resource UID changed')
        if receipt is None:
            record['resources'].append({'key': key, 'uid': obj['metadata']['uid'], 'generated': True})
            self.save()

    def remove(self, record, receipt):
        obj = self.kube.get(tuple(receipt['key']))
        if obj is None:
            return True
        if obj['metadata'].get('uid') != receipt['uid'] or not receipt['uid']:
            raise ValueError('Preview deletion target UID changed')
        if receipt.get('generated'):
            owned(obj, record['approval'], self.object['metadata']['uid'], receipt['uid'])
            if receipt['key'][1] == 'Application':
                owned(obj, record['approval'], self.object['metadata']['uid'], receipt['uid'])
            elif not obj['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith(names(record['approval'])['name'] + ':'):
                raise ValueError('Preview workload source owner changed')
        else:
            owned(obj, record['approval'], self.object['metadata']['uid'], receipt['uid'])
        if obj['metadata'].get('finalizers') not in (None, [], ['foregroundDeletion']):
            raise ValueError('Unexpected finalizer blocks preview deletion')
        if not obj['metadata'].get('deletionTimestamp'):
            if receipt['key'][1] in ('Deployment', 'Service', 'ServiceAccount', 'Gateway'):
                namespace = names(record['approval'])['namespace']
                namespace_receipt = next(r for r in record['resources'] if r['key'][1] == 'Namespace')
                namespace_disposable(self.kube.namespace_inventory(namespace),
                    {r['uid'] for r in record['resources'] if r['uid']}, namespace_receipt['uid'])
            self.kube.delete(tuple(receipt['key']), receipt['uid'], obj['metadata']['resourceVersion'],
                orphan=receipt['key'][1] in ('ApplicationSet', 'Application', 'Namespace'))
        return False

    def retire(self, record, identity_state):
        self.capture_workloads(record)
        # Stop native regeneration before removing any workloads.
        for kind in ('HTTPRoute', 'ApplicationSet', 'Application', 'Deployment', 'Service', 'ServiceAccount', 'Gateway'):
            for receipt in record['resources']:
                if receipt['key'][1] == kind and not self.remove(record, receipt):
                    return
        for receipt in record['resources']:
            if receipt['key'][1] not in ('Namespace', 'ApplicationSet', 'Application', 'HTTPRoute', 'RoleBinding', 'Deployment', 'Service', 'ServiceAccount', 'Gateway'):
                if not self.remove(record, receipt):
                    return
        identity_entry = (identity_state or {}).get('entries', {}).get(record['approval']['instance'])
        # No client was ever provisioned when identity has no entry and execution never activated.
        if (identity_entry is None and record.get('activatedAt') is not None) or (identity_entry is not None and (
                identity_entry.get('approvalDigest') != record['approvalDigest'] or identity_entry.get('phase') != 'retired')):
            return
        namespace_receipt = next((r for r in record['resources'] if r['key'][1] == 'Namespace'), None)
        if namespace_receipt:
            namespace = self.kube.get(tuple(namespace_receipt['key']))
            if namespace:
                owned(namespace, record['approval'], self.object['metadata']['uid'], namespace_receipt['uid'])
                namespace_disposable(self.kube.namespace_inventory(namespace['metadata']['name']),
                    {r['uid'] for r in record['resources'] if r['uid']}, namespace_receipt['uid'])
                if not self.remove(record, namespace_receipt):
                    return
        record.clear()
        record.update(phase='retired', approvalDigest=self.retiring_digest, expiresAt=self.retiring_expiry)
        self.save()

    def identity_state(self):
        obj = self.kube.get(('v1', 'ConfigMap', 'cloudlab-identity', IDENTITY_STATE))
        if obj and obj.get('metadata', {}).get('labels', {}).get('cloudlab.io/owner') != 'cloudlab-preview-identity':
            raise ValueError('Preview identity state has conflicting ownership')
        return json.loads(obj['data']['state.json']) if obj else None

    def local_retirements(self, identity_state, desired=None):
        failures = 0
        for instance, record in self.state['entries'].items():
            if record['phase'] == 'retired':
                continue
            try:
                row = record['approval']
                reason = (retirement(row, desired.get(instance), None, self.now) if desired is not None
                          else 'expired' if self.now >= row['expiresAt'] else None)
                if reason or record['phase'] == 'retiring':
                    record.update(phase='retiring', reason=record.get('reason', reason))
            except ValueError:
                failures += 1
        self.save()
        for record in self.state['entries'].values():
            if record['phase'] != 'retiring':
                continue
            try:
                self.retiring_digest, self.retiring_expiry = record['approvalDigest'], record['approval']['expiresAt']
                self.retire(record, identity_state)
            except (ValueError, RuntimeError):
                failures += 1
        return failures

    def unavailable_input(self):
        failures = self.local_retirements(self.identity_state())
        return {'active': sum(r['phase'] == 'active' for r in self.state['entries'].values()),
                'retiring': sum(r['phase'] == 'retiring' for r in self.state['entries'].values()),
                'discovery_unavailable': 0, 'rejected': 0, 'failures': failures + 1, 'input_unavailable': 1}

    def run(self, settings, platform_repository):
        try:
            catalog(settings)
            binding = {key: settings[key] for key in ('hostname', 'issuer')}
            if self.state.get('settings', binding) != binding:
                return self.unavailable_input()
        except (ValueError, TypeError, KeyError):
            return self.unavailable_input()
        self.state['settings'] = binding
        self.save()
        desired = {row['instance']: row for row in settings['approvals']}
        interval = 60 if settings['privateDiscovery'] else ANONYMOUS_INTERVAL
        self.state['checks'] = {key: value for key, value in self.state.get('checks', {}).items() if key in desired}
        observations = {}
        unavailable = 0
        rejected = 0
        identity_state = self.identity_state()
        # Persist every local retirement before any provider request can block.
        failures = self.local_retirements(identity_state, desired)

        # Failed discovery still consumes this budget; pending approvals cannot
        # starve expiry or turn an outage into an unbounded provider loop.
        discovery_budget = MAX_ACTIVE if self.now - self.state.get('providerCheckAt', 0) >= interval else 0
        candidate_budget = MAX_ACTIVE - sum(record['phase'] != 'retired' for record in self.state['entries'].values())
        for row in settings['approvals']:
            if not discovery_budget or candidate_budget <= 0 or row['instance'] in self.state['entries']:
                continue
            if not row['createdAt'] <= self.now < row['expiresAt']:
                continue
            if not self.github.allows(row, self.now):
                unavailable += 1
                continue
            if (sum(entry['phase'] != 'retired' for entry in self.state['entries'].values()) >= MAX_ACTIVE or
                    self.now - self.state['checks'].get(row['instance'], 0) < interval):
                continue
            discovery_budget -= 1
            candidate_budget -= 1
            self.state['providerCheckAt'] = self.now
            self.state['checks'][row['instance']] = self.now
            self.save()
            try:
                observations[row['instance']] = self.github.verified(row)
                self.state = enroll(self.state, row, self.now)
                self.save()
            except RuntimeError:
                unavailable += 1
            except ValueError:
                rejected += 1
        for instance, record in self.state['entries'].items():
            try:
                if record['phase'] == 'retired':
                    if instance in desired and record['approvalDigest'] != digest(canonical(desired[instance])):
                        raise ValueError('Retired preview instance cannot be reused')
                    continue
                if record['phase'] == 'retiring':
                    continue
                row = record['approval']
                pull = observations.get(instance)
                if record['phase'] != 'retiring' and self.now < row['expiresAt'] and instance in desired:
                    if pull is None and self.now - self.state['checks'].get(instance, 0) >= interval:
                        if not discovery_budget:
                            continue
                        discovery_budget -= 1
                        self.state['providerCheckAt'] = self.now
                        self.state['checks'][instance] = self.now
                        self.save()
                        try:
                            pull = self.github.pull(row)
                        except RuntimeError:
                            unavailable += 1
                reason = retirement(row, desired.get(instance), pull, self.now)
                if reason or record['phase'] == 'retiring':
                    record.update(phase='retiring', reason=record.get('reason', reason))
                    self.save()
                    self.retiring_digest, self.retiring_expiry = record['approvalDigest'], row['expiresAt']
                    self.retire(record, identity_state)
                    continue
                if pull is None:
                    continue
                if not self.github.allows(row, self.now):
                    unavailable += 1
                    continue
                if record['phase'] == 'pending' and instance not in observations:
                    # Fetch exact bytes again immediately before creating execution authority.
                    try:
                        validate_pull(row, pull)
                        verify_blob(row, self.github.blob(row))
                    except RuntimeError:
                        unavailable += 1
                        continue
                declarations = resources(row, settings, platform_repository, self.object['metadata']['uid'])
                for obj in declarations:
                    if obj['kind'] != 'ApplicationSet':
                        self.materialize(record, obj)
                client = (identity_state or {}).get('entries', {}).get(instance)
                if (client and client.get('phase') == 'active' and client.get('approvalDigest') == record['approvalDigest'] and
                        type(client.get('verifiedAt')) is int and 0 <= self.now - client['verifiedAt'] <= 600 and self.waypoint_ready(row)):
                    for obj in declarations:
                        if obj['kind'] == 'ApplicationSet':
                            self.materialize(record, obj)
                    record.update(activatedAt=record.get('activatedAt', self.now))
                    if self.publication_ready(row, settings):
                        record['phase'] = 'active'
                    self.save()
                    self.capture_workloads(record)
            except (ValueError, RuntimeError):
                failures += 1
                continue
        return {'active': sum(r['phase'] == 'active' for r in self.state['entries'].values()),
                'retiring': sum(r['phase'] == 'retiring' for r in self.state['entries'].values()),
                'discovery_unavailable': unavailable, 'rejected': rejected, 'failures': failures}


def run():
    kube = Kubernetes()
    controller = Controller(kube, None, int(time.time()))
    approval_obj = kube.get(('v1', 'ConfigMap', 'argocd', APPROVALS))
    if not approval_obj or approval_obj['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER:
        return controller.unavailable_input()
    try:
        settings = catalog(json.loads(approval_obj['data']['catalog.json']))
        platform_repository = approval_obj['data']['platformRepository']
    except (ValueError, TypeError, KeyError):
        return controller.unavailable_input()
    token, lease = '', None
    if settings['privateDiscovery']:
        try:
            token = Path('/discovery/TOKEN').read_text().strip()
            lease = json.loads(Path('/discovery/lease.json').read_text())
        except (OSError, ValueError):
            pass
    controller.github = GitHub(token, private=settings['privateDiscovery'], lease=lease)
    return controller.run(settings, platform_repository)


if __name__ == '__main__':
    try:
        result = run()
        print(json.dumps(result, sort_keys=True))
        if result['failures']:
            raise SystemExit(1)
    except Exception:
        raise SystemExit('Preview reconciliation failed; private diagnostics withheld') from None

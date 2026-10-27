"""Read bounded owned preview resources and real identity retirement state."""
import copy
import json
import re
import time
from urllib.parse import quote, urlencode

from playbooks.previews.files import contract


def validate(request):
    if (not isinstance(request, dict) or set(request) != {'action', 'nonce', 'realm', 'approvals', 'expected', 'revision'} or
            request['action'] != 'lifecycle' or request['realm'] != 'applications' or
            not re.fullmatch('[a-f0-9]{32}', request.get('nonce', '')) or
            not isinstance(request['approvals'], list) or len(request['approvals']) > 4 or
            not re.fullmatch('[a-f0-9]{40}', request.get('revision', '')) or
            not isinstance(request['expected'], dict)):
        raise ValueError('Lifecycle observation requires its bounded exact fixture request')
    ids = []
    for row in request['approvals']:
        contract.approval(row)
        if row['definition']['profile'] != 'synthetic':
            raise ValueError('Lifecycle fixture observes only synthetic owned previews')
        ids.append(row['instance'])
    if len(set(ids)) != len(ids) or set(request['expected']) - set(ids):
        raise ValueError('Lifecycle observation repeats or exceeds its owned instances')


def resource(kind, version):
    return kind.lower() + ('.' + version.split('/')[0] if '/' in version else '')


def secret_presence(namespace):
    from playbooks.istio.files.kube import kube
    text = kube('get', 'secrets', '-n', namespace, '-o=jsonpath={range .items[*]}{.metadata.uid}{"\\n"}{end}')
    if len(text) > 8192:
        raise ValueError('Preview Secret metadata exceeds its observation bound')
    return bool(text.strip())


def inspect_row(row, settings, lifecycle, identity, expected, get, find_client, get_client, now, platform, *, secrets_present=None):
    from playbooks.istio.files.kube import contains
    from playbooks.previews.files.lifecycle import owned
    from playbooks.previews.files.resources import resources, private_route, workload_keys
    from playbooks.keycloak.files.preview_clients import matching, representation_matches
    n, fingerprint = contract.names(row), contract.digest(contract.canonical(row))
    runtime = json.loads(lifecycle['data']['state.json'])['entries'].get(row['instance'], {})
    clients = json.loads(identity['data']['state.json'])['entries'].get(row['instance'], {}) if identity else {}
    for record in (runtime, clients):
        if record and (record.get('approvalDigest') != fingerprint or ('approval' in record and record['approval'] != row)):
            raise ValueError('Runtime approval identity changed')
    state_uid = lifecycle['metadata']['uid']
    prior = expected.get('active', {})
    prior_uids = prior.get('uids', {})
    runtime_uids = {'/'.join((key[0], key[1], key[2] or '', key[3])): receipt['uid']
                    for receipt in runtime.get('resources', []) for key in [receipt['key']]}
    observed, uids = {}, {}
    declarations = resources(row, settings, platform, state_uid) + [private_route(row, settings, state_uid)]
    keys = [(obj['apiVersion'], obj['kind'], obj['metadata'].get('namespace'), obj['metadata']['name']) for obj in declarations]
    keys += [('argoproj.io/v1alpha1', 'Application', 'argocd', n['name']), *workload_keys(row)]
    for version, kind, namespace, name in keys:
        key = '/'.join((version, kind, namespace or '', name))
        obj = get(resource(kind, version), name, namespace)
        if obj:
            expected_uid = prior_uids.get(key) or runtime_uids.get(key)
            if not expected_uid:
                raise ValueError('Observed resource lacks an authoritative creation UID receipt')
            owned(obj, row, state_uid, expected_uid)
            uids[key] = obj['metadata']['uid']
            observed[kind + '/' + name] = obj
    # A namespace cannot disappear while an exact generated control object survives.
    absent_resources = not observed
    found = find_client(n['client'])
    if not isinstance(found, list) or len(found) > 1:
        raise ValueError('Exact preview client lookup is ambiguous')
    history = [expected, *(expected.get(key, {}) for key in ('active', 'disabled', 'latest'))]
    identifiers = [event['knownUUID'] for event in history if 'knownUUID' in event]
    identifiers += [event['client'].get('id') for event in history if 'client' in event]
    if clients.get('uuid') is not None:
        identifiers.append(clients['uuid'])
    if any(not isinstance(value, str) or not re.fullmatch('[A-Za-z0-9-]{1,100}', value) for value in identifiers):
        raise ValueError('Historical client UUID is malformed')
    known_uuids = set(identifiers)
    if len(known_uuids) > 1:
        raise ValueError('Historical client UUID ownership is ambiguous')
    uuid = next(iter(known_uuids), None)
    by_uuid = get_client(uuid) if uuid else None
    if found:
        record = {'clientId': n['client'], 'approval': row, 'approvalDigest': fingerprint, 'uuid': uuid}
        if (not matching(found[0], record) or uuid and (not by_uuid or not matching(by_uuid, record) or
                by_uuid.get('id') != found[0]['id'] or by_uuid.get('enabled') != found[0].get('enabled'))):
            raise ValueError('Observed client UUID/ownership changed')
        client = found[0]
    else:
        if by_uuid is not None:
            raise ValueError('Expected client UUID still exists under another client identifier')
        client = None
    result = {'approvalDigest': fingerprint, 'observedAt': now, 'phase': runtime.get('phase'),
        'identityPhase': clients.get('phase'), 'reason': runtime.get('reason'), 'uids': uids,
        'active': False, 'disabled': False, 'absent': False, 'cleanupOnlyAbsent': False}
    if client:
        result['client'] = {'id': client['id'], 'clientId': client['clientId'], 'enabled': client.get('enabled')}
    known_uuid = uuid or (client or {}).get('id')
    if known_uuid is not None:
        if not isinstance(known_uuid, str) or not re.fullmatch('[A-Za-z0-9-]{1,100}', known_uuid):
            raise ValueError('Observed client UUID is malformed')
        result['knownUUID'] = known_uuid
    if runtime.get('phase') == 'active' and clients.get('phase') == 'active':
        if not client or client.get('enabled') is not True or not representation_matches(client, row, settings):
            raise ValueError('Active preview client representation differs')
        for desired in declarations:
            key = desired['kind'] + '/' + desired['metadata']['name']
            obj = observed.get(key)
            if not obj or not contains(obj, desired):
                raise ValueError('Active preview resource differs from its platform declaration')
        app = observed.get('Application/' + n['name'], {})
        source = app.get('spec', {}).get('source', {})
        if (source.get('repoURL') != platform or source.get('targetRevision') != row['platformRevision'] or source.get('path') != 'charts/service' or
                app.get('spec', {}).get('project') != n['name'] or
                app['spec'].get('destination') != {'server': 'https://kubernetes.default.svc', 'namespace': n['namespace']} or
                app.get('status', {}).get('sync', {}).get('status') != 'Synced' or
                app['status']['sync'].get('revision') != row['platformRevision'] or app['status'].get('health', {}).get('status') != 'Healthy'):
            raise ValueError('Active generated Application differs from approved platform source')
        deployment = observed.get('Deployment/preview', {})
        podspec = deployment.get('spec', {}).get('template', {}).get('spec', {})
        containers = podspec.get('containers', [])
        if (len(containers) != 1 or containers[0].get('image') != contract.IMAGE or podspec.get('automountServiceAccountToken') is not False or
                deployment.get('status', {}).get('readyReplicas') != 1):
            raise ValueError('Active synthetic workload is not restricted and ready')
        environment = {value['name']: value.get('value') for value in containers[0].get('env', [])}
        if environment.get('CLOUDLAB_SOURCE_SHA') != row['sourceSha'] or environment.get('PREVIEW_MESSAGE') != row['definition']['message']:
            raise ValueError('Workload did not execute the approved synthetic revision')
        replicas = (get('replicasets.apps', namespace=n['namespace']) or {}).get('items', [])
        deployment_uid = deployment['metadata']['uid']
        replica_uids = {obj['metadata']['uid'] for obj in replicas if any(
            ref.get('uid') == deployment_uid and ref.get('kind') == 'Deployment' for ref in obj['metadata'].get('ownerReferences', []))}
        pods = [obj for obj in (get('pods', namespace=n['namespace']) or {}).get('items', [])
                if obj['metadata'].get('labels', {}).get('app.kubernetes.io/name') == 'preview']
        if len(pods) != 1:
            raise ValueError('Synthetic preview must have one observed workload Pod')
        for pod in pods:
            if (not any(ref.get('kind') == 'ReplicaSet' and ref.get('uid') in replica_uids for ref in pod['metadata'].get('ownerReferences', [])) or
                    pod.get('spec', {}).get('automountServiceAccountToken') is not False or
                    pod.get('status', {}).get('phase') != 'Running'):
                raise ValueError('Observed Pod is not the ready owned restricted workload')
            key = 'v1/Pod/' + n['namespace'] + '/' + pod['metadata']['name']
            if prior_uids.get(key, pod['metadata']['uid']) != pod['metadata']['uid']:
                raise ValueError('Captured workload Pod identity changed')
            uids[key] = pod['metadata']['uid']
        if (secrets_present or secret_presence)(n['namespace']) or (get('persistentvolumeclaims', namespace=n['namespace']) or {}).get('items'):
            raise ValueError('Preview contains credential or persistent data resources')
        result['active'] = True
    if clients.get('phase') == 'disabled':
        disabled_at = clients.get('disabledAt')
        if not client or client.get('enabled') is not False or type(disabled_at) is not int or not 0 < disabled_at <= now:
            raise ValueError('Confirmed disabled UUID/time evidence is unavailable')
        result.update(disabled=True, disabledAt=disabled_at)
    if runtime.get('phase') == 'retired' and clients.get('phase') == 'retired' and absent_resources and client is None:
        result['cleanupOnlyAbsent'] = True
        disabled = expected.get('disabled', {})
        disabled_at = disabled.get('disabledAt')
        if (uuid and prior.get('active') is True and prior.get('client', {}).get('id') == uuid and
                disabled.get('disabled') is True and disabled.get('client', {}).get('id') == uuid and
                disabled.get('client', {}).get('enabled') is False and type(disabled_at) is int and
                0 < disabled_at <= now - 600):
            result['absent'] = True
    return result


def run(request):
    validate(request)
    from playbooks.istio.files.kube import get
    from playbooks.keycloak.files.maintenance import accepted_scoped_identity
    from playbooks.keycloak.files.configuration import private_request
    from playbooks.keycloak.files.emergency import vault_secret
    accepted_scoped_identity(revision=request['revision'])
    app = get('application.argoproj.io', 'cloudlab-identity', 'argocd')
    admin = app['spec']['source']['helm']['valuesObject']['adminHost']
    approvals = get('configmap', contract.APPROVALS, 'argocd')
    if not approvals or approvals['metadata'].get('labels', {}).get('cloudlab.io/owner') != contract.OWNER:
        raise ValueError('Current preview catalog owner is unavailable')
    settings = contract.runtime_catalog(json.loads(approvals['data']['catalog.json']))
    if admin != 'identity-admin.internal.' + settings['hostname'].split('.internal.', 1)[1]:
        raise ValueError('Preview issuer is not the accepted identity source')
    lifecycle = get('configmap', contract.STATE, 'argocd')
    identity = get('configmap', contract.IDENTITY_STATE, 'cloudlab-identity')
    for obj, owner in ((lifecycle, contract.OWNER), (identity, 'cloudlab-preview-identity')):
        if obj and (obj['metadata'].get('labels', {}).get('cloudlab.io/owner') != owner or obj['metadata'].get('ownerReferences') or
                    obj['metadata'].get('deletionTimestamp') or obj['metadata'].get('finalizers')):
            raise ValueError('Lifecycle state owner changed')
    if not lifecycle:
        raise ValueError('Lifecycle state is unavailable')
    controller = get('application.argoproj.io', 'cloudlab-previews', 'argocd')
    if (not controller or controller['metadata'].get('labels', {}).get('cloudlab.io/owner') != contract.OWNER or
            controller.get('operation') or controller.get('status', {}).get('sync', {}).get('status') != 'Synced' or
            controller['status'].get('health', {}).get('status') != 'Healthy' or
            controller['spec']['sources'][0].get('targetRevision') != request['revision'] or
            controller['status']['sync'].get('revisions', [None])[0] != request['revision']):
        raise ValueError('Published preview lifecycle owner has not converged')
    platform = controller['spec']['sources'][0]['repoURL']
    origin = 'https://' + admin
    token = private_request(origin + '/realms/applications/protocol/openid-connect/token', form={
        'grant_type': 'client_credentials', 'client_id': 'realm-writer',
        'client_secret': vault_secret('keycloak-realm-writers')['applications_client_secret']})['access_token']
    endpoint = origin + '/admin/realms/applications/clients'
    def find(identifier):
        return private_request(endpoint + '?' + urlencode({'clientId': identifier, 'max': 2}), token=token)
    def by_uuid(uuid):
        if not isinstance(uuid, str) or not re.fullmatch('[A-Za-z0-9-]{1,100}', uuid):
            raise ValueError('Captured client UUID differs')
        status, value = private_request(endpoint + '/' + quote(uuid, safe=''), token=token, accepted_statuses=(200, 404), with_status=True)
        return None if status == 404 else value
    return {'entries': {row['instance']: inspect_row(row, settings, lifecycle, identity, request['expected'].get(row['instance'], {}),
        get, find, by_uuid, int(time.time()), platform) for row in request['approvals']}}

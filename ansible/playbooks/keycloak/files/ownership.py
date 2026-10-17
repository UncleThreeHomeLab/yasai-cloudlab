"""Identity ownership, private-input and source-handoff guards; no mutations."""
from datetime import datetime
import json
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
if not (ROOT / 'platform').is_dir():
    ROOT = ROOT.parent
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
sys.path.insert(0, str(ROOT))
from playbooks.data.files.control import identity
from playbooks.keycloak.files.configuration import compile_state, exact_url
from playbooks.keycloak.files.maintenance import APP, NAMESPACE, OWNER
from playbooks.istio.files.kube import application_ready, condition, get
from playbooks.argocd.files.private_sources import PEM_TEMPLATE

PHASES = ('server', 'bootstrap', 'primary', 'scoped')


def completed_job_retention(job, crons, retired, now):
    metadata, status = job.get('metadata', {}), job.get('status', {})
    if (metadata.get('namespace') != NAMESPACE or metadata.get('deletionTimestamp') or
            not metadata.get('uid') or not metadata.get('resourceVersion') or status.get('active') or
            job.get('spec', {}).get('ttlSecondsAfterFinished') is not None):
        return []
    finished = [c for c in status.get('conditions', []) if c.get('type') in ('Complete', 'Failed') and c.get('status') == 'True']
    if len(finished) != 1:
        return []
    try:
        successes = [datetime.fromisoformat(crons[name]['status']['lastSuccessfulTime'].replace('Z', '+00:00')).timestamp()
                     for name in ('identity-health', 'identity-reconcile')]
        completed = datetime.fromisoformat(finished[0]['lastTransitionTime'].replace('Z', '+00:00')).timestamp()
        if any(not 0 <= now - success <= 900 for success in successes) or completed >= min(successes):
            return []
        ttl = crons['identity-health']['spec']['jobTemplate']['spec']['ttlSecondsAfterFinished']
    except (KeyError, TypeError, ValueError):
        return []
    if type(ttl) is not int or not 300 <= ttl <= 86400:
        raise RuntimeError('Completed identity jobs require bounded declared retention')
    owners = metadata.get('ownerReferences', [])
    cron_owned = any(ref.get('kind') == 'CronJob' and ref.get('apiVersion') == 'batch/v1' and ref.get('controller') is True and
                     ref.get('name') in ('identity-health', 'identity-reconcile') and ref.get('uid') and
                     ref['uid'] == crons[ref['name']].get('metadata', {}).get('uid') for ref in owners)
    hook_owned = (retired and not owners and metadata.get('name') == 'identity-bootstrap-retirement' and
                  metadata.get('annotations', {}).get('argocd.argoproj.io/tracking-id') ==
                  APP + ':batch/Job:' + NAMESPACE + '/identity-bootstrap-retirement' and
                  job.get('spec', {}).get('template', {}).get('spec', {}).get('serviceAccountName') == 'identity-writer')
    if not cron_owned and not hook_owned:
        return []
    return [{'op': 'test', 'path': '/metadata/uid', 'value': metadata['uid']},
            {'op': 'test', 'path': '/metadata/resourceVersion', 'value': metadata['resourceVersion']},
            {'op': 'add', 'path': '/spec/ttlSecondsAfterFinished', 'value': ttl}]


def check_private_owner(kind, actual, saved):
    metadata = actual.get('metadata', {}) if actual else {}
    finalizers = metadata.get('finalizers') or []
    expected = ['externalsecrets.external-secrets.io/externalsecret-cleanup'] if kind == 'ExternalSecret' else []
    if (saved and (not actual or metadata.get('uid') != saved)) or (actual and (
            metadata.get('labels', {}).get('cloudlab.io/owner') != OWNER or
            (finalizers and finalizers != expected) or metadata.get('ownerReferences') or
            metadata.get('deletionTimestamp'))):
        raise RuntimeError('Private identity source owner conflicts or changed identity')


def private_resources(payload):
    name = 'cloudlab-identity-private'
    metadata = lambda: {'name': name, 'namespace': 'argocd', 'labels': {'cloudlab.io/owner': OWNER}}
    project = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'AppProject', 'metadata': metadata(),
        'spec': {'sourceRepos': [payload['private_repository']],
            'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': NAMESPACE}],
            'clusterResourceWhitelist': [], 'namespaceResourceWhitelist': [{'group': '', 'kind': 'ConfigMap'}]}}
    credential = {'apiVersion': 'external-secrets.io/v1', 'kind': 'ExternalSecret', 'metadata': metadata(),
        'spec': {'refreshInterval': '24h', 'secretStoreRef': {'name': 'cloudlab', 'kind': 'ClusterSecretStore'},
            'target': {'name': name, 'creationPolicy': 'Owner', 'deletionPolicy': 'Retain',
                'template': {'engineVersion': 'v2', 'mergePolicy': 'Replace',
                    'metadata': {'labels': {'argocd.argoproj.io/secret-type': 'repository'}},
                    'data': {'type': 'git', 'url': payload['private_repository'], 'project': name,
                        'githubAppID': '{{ .APP_ID }}', 'githubAppInstallationID': '{{ .INSTALLATION_ID }}',
                        'githubAppPrivateKey': PEM_TEMPLATE}}},
            'dataFrom': [{'extract': {'key': 'github-argocd'}}]}}
    app = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application', 'metadata': metadata(),
        'spec': {'project': name, 'source': {'repoURL': payload['private_repository'],
                'targetRevision': payload['private_branch'], 'path': 'identity',
                'directory': {'include': 'configmap.yaml'}},
            'destination': {'server': 'https://kubernetes.default.svc', 'namespace': NAMESPACE},
            'syncPolicy': {'automated': {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False},
                'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true']}}}
    return [project, credential, app]


def discover():
    import base64
    import ipaddress
    certificate = get('certificate.cert-manager.io', 'cloudlab-gateway', 'cloudlab-gateway-private')
    if not condition(certificate, 'Ready'):
        raise RuntimeError('Independent private TLS must be ready before identity')
    names = certificate['spec']['dnsNames']
    if (len(names) != 2 or not names[0].startswith('*.internal.') or
            names[1] != 'login.' + names[0][11:]):
        raise RuntimeError('Private TLS domain contract changed')
    domain = names[0][11:]
    proxies = []
    nodes = {node['metadata']['name']: node for node in get('nodes')['items']}
    for namespace in ('cloudlab-gateway-public', 'cloudlab-gateway-private'):
        for pod in get('pods', namespace=namespace)['items']:
            if pod['metadata'].get('labels', {}).get('gateway.networking.k8s.io/gateway-name') == 'cloudlab':
                value = pod.get('status', {}).get('podIP')
                if value:
                    address = ipaddress.ip_address(value)
                    ranges = nodes[pod['spec']['nodeName']]['spec'].get('podCIDRs') or [nodes[pod['spec']['nodeName']]['spec']['podCIDR']]
                    matching = [ipaddress.ip_network(cidr, strict=True) for cidr in ranges
                                if ipaddress.ip_network(cidr, strict=True).version == address.version
                                and address in ipaddress.ip_network(cidr, strict=True)]
                    if len(matching) != 1 or pod['spec'].get('hostNetwork'):
                        raise RuntimeError('Gateway proxy source must belong to its verified node Pod range')
                    # Gateway-only NetworkPolicy selects the peers; node Pod ranges
                    # retain forwarding trust when the sole gateway owner replaces Pods.
                    proxies.append(str(matching[0]))
    if not proxies:
        raise RuntimeError('Verified gateway proxy peers are unavailable')
    cluster = get('cluster.postgresql.cnpg.io', 'cloudlab-postgres', 'cloudlab-data')
    ca = get('secret', 'cloudlab-postgres-ca', 'cloudlab-data')
    database = get('database.postgresql.cnpg.io', 'keycloak', 'cloudlab-data')
    if not condition(cluster, 'Ready') or not ca or not database:
        raise RuntimeError('Ready CNPG database and certificate authority are required')
    if not any(ref.get('uid') == cluster['metadata']['uid'] for ref in ca['metadata'].get('ownerReferences', [])):
        raise RuntimeError('Database CA is not owned by the verified CNPG cluster')
    return {'loginHost': 'login.' + domain, 'adminHost': 'identity-admin.internal.' + domain,
            'database': database['spec']['name'], 'databaseRole': database['spec']['owner'],
            'databaseHost': 'cloudlab-postgres-rw.cloudlab-data.svc.cluster.local', 'databasePort': 5432,
            'databaseCA': base64.b64decode(ca['data']['ca.crt'], validate=True).decode(),
            'trustedProxyAddresses': sorted(set(proxies))}


def application(payload, phase, retired=False, retired_item=''):
    import ipaddress
    if phase not in PHASES:
        raise ValueError('Unsupported identity bootstrap phase')
    if type(retired) is not bool or (retired and phase != 'scoped'):
        raise ValueError('Retired bootstrap access requires normal scoped reconciliation')
    import re
    if (retired and not re.fullmatch('keycloak-emergency-[a-f0-9]{32}', retired_item)) or (not retired and retired_item):
        raise ValueError('Retirement requires its persistent ESO credential owner')
    values = payload['values']
    allowed = {'loginHost', 'adminHost', 'database', 'databaseRole', 'databaseHost',
               'databasePort', 'databaseCA', 'trustedProxyAddresses'}
    if set(values) != allowed:
        raise ValueError('Runtime identity requires its complete bounded input contract')
    for key in ('loginHost', 'adminHost'):
        exact_url('https://' + values[key] + '/')
        if '/' in values[key] or ':' in values[key]:
            raise ValueError('Identity host must be a DNS name')
    if (not values['loginHost'].startswith('login.') or
            values['adminHost'] != 'identity-admin.internal.' + values['loginHost'][6:]):
        raise ValueError('Identity hosts must use the designated owned-domain contract')
    for key in ('database', 'databaseRole'):
        identity(values[key])
    if (values['databaseHost'] != 'cloudlab-postgres-rw.cloudlab-data.svc.cluster.local'
            or values['databasePort'] != 5432 or not values['databaseCA'] or not values['trustedProxyAddresses']):
        raise ValueError('Identity requires the verified CNPG TLS and proxy-peer inputs')
    if not isinstance(values['trustedProxyAddresses'], list) or not 1 <= len(values['trustedProxyAddresses']) <= 8:
        raise ValueError('Proxy trust must contain a bounded exact peer inventory')
    for value in values['trustedProxyAddresses']:
        network = ipaddress.ip_network(value, strict=True)
        if network.prefixlen < (24 if network.version == 4 else 64) or not network.network_address.is_private:
            raise ValueError('Proxy trust must use bounded verified private gateway Pod ranges')
    desired = dict(values, enabled=True, operatorEnabled=False, serverEnabled=True,
                   maintenance=False, reconciliationEnabled=phase != 'server', bootstrapMode=phase in ('bootstrap', 'primary'),
                   primaryAdminEnabled=phase == 'primary', privateStateEnabled=phase != 'server', bootstrapAdminEnabled=not retired)
    desired['telemetryEnabled'] = payload.get('telemetry_enabled', False)
    if retired:
        desired['retiredEmergencyItem'] = retired_item
    return {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
        'metadata': {'name': APP, 'namespace': 'argocd', 'labels': {'cloudlab.io/owner': OWNER}},
        'spec': {'project': APP, 'source': {'repoURL': payload['repository'], 'targetRevision': payload['branch'],
            'path': 'platform/identity/keycloak', 'helm': {'releaseName': APP, 'valuesObject': desired}},
            'destination': {'server': 'https://kubernetes.default.svc', 'namespace': NAMESPACE},
            'syncPolicy': {'automated': {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False},
                'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true',
                                'RespectIgnoreDifferences=true'],
                'retry': {'limit': 5, 'backoff': {'duration': '30s', 'factor': 2, 'maxDuration': '2m'}}}}}


def prerequisites(payload):
    # Require recovery evidence on disk; controller health alone is insufficient.
    backup = json.loads(Path('/var/lib/cloudlab/application-data/longhorn-monthly-receipt.json').read_text())
    if not backup.get('retention_complete') or not backup.get('restore', {}).get('physical_restore'):
        raise RuntimeError('Verified CNPG physical recovery must precede identity')
    access = json.loads(Path('/var/lib/cloudlab/connectivity/receipts/acceptance.json').read_text())
    if not access.get('verified_at') or not access.get('external_binding'):
        raise RuntimeError('Independent public/private access proof must precede identity')
    for name in ('cloudlab-keycloak-operator', 'cloudlab-data-configuration', 'cloudlab-access', 'cloudlab-argocd'):
        if not application_ready(name, payload['revision']):
            raise RuntimeError('Identity prerequisite Application is not converged')
    data = get('application.argoproj.io', 'cloudlab-data-configuration', 'argocd')['spec']['source']['helm']['valuesObject']
    if data.get('identity') != {'enabled': True, 'database': payload['values']['database'], 'role': payload['values']['databaseRole']}:
        raise RuntimeError('Identity dedicated CNPG contract is not enabled by its data owner')
    database = get('database.postgresql.cnpg.io', 'keycloak', 'cloudlab-data') or {}
    if (not database.get('status', {}).get('applied') or
            database.get('status', {}).get('observedGeneration') != database.get('metadata', {}).get('generation')):
        raise RuntimeError('Dedicated identity database is not ready')


def private_inputs(payload):
    import base64
    app = get('application.argoproj.io', 'cloudlab-identity-private', 'argocd') or {}
    revision = app.get('status', {}).get('sync', {}).get('revision')
    if (app.get('spec', {}).get('source', {}).get('repoURL') != payload['private_repository'] or
            not revision or not application_ready('cloudlab-identity-private', revision)):
        raise RuntimeError('Required private identity source is unavailable or not converged; no realm imports allowed')
    private = get('configmap', 'identity-private-state', NAMESPACE)
    secrets = get('secret', 'keycloak-client-secrets', NAMESPACE)
    if not private or not secrets:
        raise RuntimeError('Ready private inventory and vault client credentials are required')
    if not private['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith('cloudlab-identity-private:'):
        raise RuntimeError('Private inventory must belong to its designated Argo source')
    external = get('externalsecret.external-secrets.io', 'keycloak-client-secrets', NAMESPACE)
    if not condition(external, 'Ready') or not any(ref.get('uid') == external['metadata']['uid']
            for ref in secrets['metadata'].get('ownerReferences', [])):
        raise RuntimeError('Client credentials must be owned by ready ESO')
    source = json.loads(private['data']['desired_state'])
    revoked = json.loads(private['data']['revocations'])
    credentials = json.loads(base64.b64decode(secrets['data']['client_secrets'], validate=True))
    for realm in ('platform', 'applications'):
        compile_state(realm, payload['values']['loginHost'], source, credentials, revoked)
    return source, revoked, revision


def branch_handoff_patches(current, desired, retirement):
    if (not retirement or current['spec']['source']['targetRevision'] != retirement['revision'] or
            current['spec']['source']['targetRevision'] == desired['spec']['source']['targetRevision']):
        return []
    values = current['spec']['source']['helm']['valuesObject']
    if (retirement.get('phase') != 'accepted' or current['metadata']['uid'] != retirement['application_uid'] or
            current.get('operation') or values.get('maintenance') or values.get('operation')):
        raise RuntimeError('Branch handoff requires accepted retirement and an idle unchanged Application')
    # The phase's Update ownership otherwise conflicts with normal server-side Apply.
    return [
        {'op': 'test', 'path': '/metadata/uid', 'value': retirement['application_uid']},
        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']},
        {'op': 'test', 'path': '/spec/source/targetRevision', 'value': retirement['revision']},
        {'op': 'replace', 'path': '/spec/source/targetRevision',
         'value': desired['spec']['source']['targetRevision']}]


def enrollment_handoff(current, state, directory):
    """Only a completed nonce-owned enrollment may release its source pin."""
    revision = current['spec']['source']['targetRevision']
    if not state or revision != state.get('revision'):
        return None
    accepted = []
    for path in directory.glob('proof-*.json'):
        record = json.loads(path.read_text())
        nonce = record.get('nonce')
        if (not isinstance(nonce, str) or not re.fullmatch('[a-f0-9]{32}', nonce) or
                path.name != 'proof-'+nonce+'.json'):
            raise RuntimeError('Disposable source checkpoint identity is malformed')
        if record.get('revision') == revision and record.get('phase') in ('prepared', 'created'):
            raise RuntimeError('Complete pending disposable enrollment before source handoff')
        if record.get('phase') == 'enrolled' and record.get('revision') == revision:
            if record.get('application_uid') != state['uid'] or not record.get('user_id'):
                raise RuntimeError('Disposable source checkpoint resource identity changed')
            accepted.append(record)
    if not accepted:
        return None
    return {'phase':'accepted','revision':revision,'application_uid':state['uid']}

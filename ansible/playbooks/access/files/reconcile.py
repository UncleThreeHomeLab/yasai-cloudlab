"""Control-machine connectivity reconciler: tailnet, private DNS, public DNS.

Reads accepted Git revisions only. Tailnet and private DNS converge
automatically. Cloudflare plans every cycle and applies the approved
exposure state's exact plan with no second operator command once a merged
platform/access/cloudflare-approval.yaml binds its {revision, plan}
(merged PR plus exact exposure-state and plan-hash binding constitutes
approval). Unreviewed or mismatched state never applies. Invalid or
unreachable sources retain last-valid state and report blocked; they
never delete, grant, or publish.

Approval ceremony: merge the exposure change; read the pending digest from
this reconciler's status; merge a second PR binding {revision, plan} for
the current main SHA; the standing loop applies it and reports
convergence. The binding approves the exposure bytes, not the HEAD SHA:
merging the approval PR keeps those bytes identical, so the approval
stays satisfiable; any exposure or plan change voids it until rebound.

Activation ceremony (first private policy): capture the current tailnet ACL
and split-DNS hashes; merge private platform/access/policy.yaml; run `once`;
run `verify` and confirm grants, split DNS, resolver answers, and declared
access tests; rerun `once` for zero-change idempotence; then enable `loop`.

Retirement proof: after an apply withdraws a hostname, the next cycles verify
authoritative withdrawal (Cloudflare record and tunnel entry absent; both
private resolvers answer absent) and live route absence. Edge packet
no-reachability stays a parent-run step: curl the retired hostname from an
intended client (expect failure) with a live hostname as positive control.

Preview DNS serves controller intent, never live routes: desired entries
converge on both resolvers and every successful cycle republishes status
observations copied from intent, so activation and tombstone proofs can
complete. Invalid or unreadable intent retains resolvers; entries without
both-hosts proof stay unpublished.
"""
import base64
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, '/workspace/ansible')
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tailscale/files'))
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / 'platform/delivery/previews/runtime'))

from dotenv import dotenv_values

import policy as tailnet_policy
import exposure as public_exposure
from control import API as TailnetAPI
from verify_access import ssh
from playbooks.secrets.files.vault import fields
from contract import (DNS_FRESHNESS, DNS_INTENT, DNS_INTENT_KEY, DNS_STATUS, DNS_STATUS_KEY, OWNER,
                      dns_intent, dns_status)

ROOT = Path(__file__).resolve().parents[4]
WORK = Path('/infra-work/connectivity')
INPUTS = Path('/inputs/cloudflare')
POLICY_PATH = 'platform/access/policy.yaml'
EXPOSURES_PATH = 'services/exposures.yaml'
APPROVAL_PATH = 'platform/access/cloudflare-approval.yaml'
MAX_FILE_BYTES = 65536
RESOLVER_FILES = ('dns_host.py', 'dns_render.py', 'dns_wire.py')
RESOLVER_DIR = '/var/lib/cloudlab/private-dns'


def ensure_resolver_scripts():
    """Sync the pinned resolver implementation before any remote dns_host.py call.

    Setup installs these files once, but the reconciler owns the remote
    interface (configure/check/absent/digest); a stale host copy fails every
    DNS cycle. Uploads are exact-byte copies of the reviewed repo files,
    checksum-verified after write. Any failure refuses DNS convergence.
    """
    wanted = {}
    for name in RESOLVER_FILES:
        data = (Path(__file__).resolve().parent / name).read_bytes()
        wanted[name] = (hashlib.sha256(data).hexdigest(), data.decode('utf-8'))
    for prefix in ('VM', 'VM2'):
        host = os.environ[prefix + '_HOST']
        for name, (digest, text) in wanted.items():
            try:
                observed = ssh(prefix, host, 'sha256sum ' + RESOLVER_DIR + '/' + name).split()[0]
            except (RuntimeError, IndexError):
                observed = None
            if observed == digest:
                continue
            ssh(prefix, host, 'install -m 0600 /dev/stdin ' + RESOLVER_DIR + '/' + name,
                input=text)
            observed = ssh(prefix, host, 'sha256sum ' + RESOLVER_DIR + '/' + name).split()[0]
            if observed != digest:
                raise RuntimeError('Resolver implementation sync failed on ' + prefix
                                   + '; DNS retained')


def configuration():
    values = dotenv_values(str(ROOT / '.env'), interpolate=False)
    config = {'private_repository': values.get('PRIVATE_CONFIG_REPOSITORY') or '',
              'github_token': values.get('GITHUB_PROVISION_TOKEN') or '',
              'administrator': values.get('TAILSCALE_ADMIN_LOGIN') or '',
              'human_email': values.get('CLOUDFLARE_HUMAN_EMAIL') or '',
              'identity_provider': values.get('CLOUDFLARE_IDP_ID') or '',
              'free_tier': values.get('ACCESS_FREE_TIER_CONFIRMED') or '',
              'interval': values.get('CONNECTIVITY_INTERVAL') or '300'}
    try:
        config['interval'] = int(config['interval'])
    except ValueError:
        raise RuntimeError('CONNECTIVITY_INTERVAL must be seconds') from None
    if not 60 <= config['interval'] <= 86400:
        raise RuntimeError('CONNECTIVITY_INTERVAL must be between 60 and 86400 seconds')
    if config['interval'] > DNS_FRESHNESS:
        print('CONNECTIVITY_INTERVAL exceeds preview DNS proof freshness; '
              'observations may lapse between cycles', flush=True)
    # Export file inputs for SSH and vault subprocesses; explicit environment wins.
    for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD', 'VM_PORT', 'VM_BECOME_PASSWORD',
                'VM2_HOST', 'VM2_USER', 'VM2_PASSWORD', 'VM2_PORT', 'VM2_BECOME_PASSWORD',
                'OP_SERVICE_ACCOUNT_TOKEN', 'TAILSCALE_ADMIN_LOGIN', 'GITHUB_PROVISION_TOKEN',
                'PRIVATE_CONFIG_REPOSITORY', 'CLOUDFLARE_HUMAN_EMAIL', 'CLOUDFLARE_IDP_ID',
                'ACCESS_FREE_TIER_CONFIRMED'):
        if values.get(key):
            os.environ.setdefault(key, values[key])
    for prefix in ('VM', 'VM2'):
        os.environ.setdefault(prefix + '_PORT', '22')
        os.environ.setdefault(prefix + '_BECOME_PASSWORD', os.environ.get(prefix + '_PASSWORD', ''))
    return config


def repository_slug(url):
    match = re.fullmatch(r'https://github[.]com/([A-Za-z0-9-]+)/([A-Za-z0-9_.-]+)[.]git', url or '')
    if not match:
        raise RuntimeError('Repository binding is not a designated HTTPS repository')
    return match[1] + '/' + match[2]


def public_slug():
    import yaml
    return repository_slug(yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())['repository'])


class GitHub:
    """Bounded read-only GitHub client with ETag caching; writes are refused."""

    def __init__(self, token=''):
        self.token = token
        self.cache = {}
        state = WORK / 'github-etags.json'
        if state.exists():
            self.cache = json.loads(state.read_text())

    def save(self):
        WORK.mkdir(parents=True, exist_ok=True)
        (WORK / 'github-etags.json').write_text(json.dumps(self.cache, sort_keys=True))

    def request(self, path, limit=MAX_FILE_BYTES):
        if not re.fullmatch(r'[A-Za-z0-9_./?=&-]+', path) or '..' in path:
            raise ValueError('Invalid GitHub read path')
        headers = {'Accept': 'application/vnd.github+json'}
        if self.token:
            headers['Authorization'] = 'Bearer ' + self.token
        if self.cache.get(path, {}).get('etag'):
            headers['If-None-Match'] = self.cache[path]['etag']
        request = urllib.request.Request('https://api.github.com/' + path, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read(limit + 1)
                if len(raw) > limit:
                    raise RuntimeError('GitHub response exceeds its bound')
                body = json.loads(raw)
                self.cache[path] = {'etag': response.headers.get('ETag'), 'body': body}
                self.save()
                return body
        except urllib.error.HTTPError as error:
            if error.code == 304 and 'body' in self.cache.get(path, {}):
                return self.cache[path]['body']
            if error.code == 404:
                return None
            raise RuntimeError('GitHub read failed: HTTP ' + str(error.code)) from None
        except (urllib.error.URLError, ValueError):
            raise RuntimeError('GitHub read unavailable or invalid') from None

    def ref(self, repo, branch='main'):
        document = self.request('repos/' + repo + '/git/ref/heads/' + branch)
        if not document or not re.fullmatch('[a-f0-9]{40}', document['object']['sha']):
            raise RuntimeError('Git revision is unavailable')
        return document['object']['sha']

    def contents(self, repo, path, ref, limit=4096):
        document = self.request('repos/' + repo + '/contents/' + path + '?ref=' + ref)
        if document is None:
            return None
        if (not isinstance(document, dict) or document.get('type') != 'file'
                or document.get('encoding') != 'base64'
                or type(document.get('size')) is not int
                or not 0 < document['size'] <= limit
                or not isinstance(document.get('content'), str)):
            raise RuntimeError('Git declaration requires a bounded regular file')
        raw = base64.b64decode(document['content'].replace('\r', '').replace('\n', ''), validate=True)
        if len(raw) != document['size']:
            raise RuntimeError('Git declaration size changed during transfer')
        return raw


def tailnet_addresses(api, resolvers):
    """Map inventory hostnames to distinct tailnet IPv4 addresses."""
    devices = api.request('GET', 'tailnet/-/devices')[0].get('devices', [])
    mapping, users = {}, set()
    for device in devices:
        if device.get('user'):
            users.add(device['user'])
        addresses = [a for a in device.get('addresses', [])
                     if re.fullmatch(r'100[.]\d+[.]\d+[.]\d+', a or '')]
        if device.get('hostname') in resolvers and addresses:
            mapping[device['hostname']] = addresses[0]
    if set(mapping) != set(resolvers) or len(set(mapping.values())) != 2:
        raise RuntimeError('Inventory resolvers lack distinct tailnet addresses')
    return mapping, users


def reconcile_tailnet(config, github):
    """Managed split-DNS and fixed-template grants; host policy is preserved."""
    repo = repository_slug(config['private_repository'])
    revision = github.ref(repo)
    raw = github.contents(repo, POLICY_PATH, revision)
    if raw is None:
        return {'ready': False, 'skipped': True, 'reason': 'no tailnet declaration',
                'revision': revision}
    import yaml
    try:
        declared = tailnet_policy.validate_policy(yaml.safe_load(raw))
    except Exception as error:
        raise RuntimeError('Tailnet declaration invalid; last-valid policy retained') from error
    if declared['administrator'] != config['administrator']:
        raise RuntimeError('Tailnet declaration administrator differs from the approved login')
    api = TailnetAPI('tailscale-policy')
    mapping, users = tailnet_addresses(api, declared['resolvers'])
    servers = [mapping[name] for name in declared['resolvers']]
    zone = declared['zone']
    identity_host = 'login.' + zone.removeprefix('internal.')
    current, etag = api.request('GET', 'tailnet/-/acl')
    before = api.request('GET', 'tailnet/-/dns/split-dns')[0]
    desired = tailnet_policy.candidate(current, declared, servers, users - {declared['administrator']})
    desired_dns = tailnet_policy.split_dns(
        tailnet_policy.split_dns(before, zone, servers), identity_host, servers)
    if api.request('POST', 'tailnet/-/acl/validate', desired)[0]:
        raise RuntimeError('Tailnet policy validation failed; existing grants retained')
    changed = False
    if desired != current:
        if not etag:
            raise RuntimeError('Policy API supplied no concurrency guard')
        api.request('POST', 'tailnet/-/acl', desired, etag)
        if api.request('GET', 'tailnet/-/acl')[0] != desired:
            raise RuntimeError('Tailnet grants did not converge')
        changed = True
    if before != desired_dns:
        # PATCH changes only the two owned domains; retain unrelated split DNS.
        api.request('PATCH', 'tailnet/-/dns/split-dns',
                    {name: desired_dns[name] for name in (zone, identity_host)})
        changed = True
    actual = api.request('GET', 'tailnet/-/dns/split-dns')[0]
    if (any(actual.get(name) != desired_dns[name] for name in (zone, identity_host))
            or any(actual.get(key) != value for key, value in before.items()
                   if key not in (zone, identity_host))):
        raise RuntimeError('Split DNS did not converge or unrelated configuration changed')
    return {'ready': True, 'changed': changed, 'revision': revision, 'zone': zone,
            'identity_host': identity_host, 'servers': sorted(servers), 'mapping': mapping,
            'declared': declared}


def kubectl(host_prefix, *args, binary='k3s kubectl'):
    """Read-only cluster query through the existing recovery SSH path."""
    host = os.environ[host_prefix + '_HOST']
    output = ssh(host_prefix, host, binary + ' ' + ' '.join(args) + ' -o json')
    return json.loads(output)


def kubectl_get_cm(binary):
    """Fetch the controller-owned preview DNS intent; empty output stays unreadable.

    The target is hardcoded: the agent reads intent only and writes status
    only, never the reverse.
    """
    output = ssh('VM', os.environ['VM_HOST'],
                 binary + ' get configmap ' + DNS_INTENT + ' -n argocd -o json')
    if not output.strip():
        raise RuntimeError('Preview DNS intent is unreadable; resolvers retained')
    try:
        return json.loads(output)
    except ValueError:
        raise RuntimeError('Preview DNS intent is unreadable; resolvers retained') from None


def read_dns_intent(binary):
    """Whole-generation preview DNS intent; invalid input retains resolvers."""
    try:
        return dns_intent(json.loads(kubectl_get_cm(binary)['data'][DNS_INTENT_KEY]))
    except (ValueError, TypeError, KeyError, AttributeError):
        raise RuntimeError('Preview DNS intent is invalid; resolvers retained') from None


def publish_dns_status(binary, intent, published, absent, hostnames, now):
    """Publish observations copied from validated intent; failure keeps prior status.

    Gateways and hostnames are copies of the intent values, never
    reconstructed, after the caller verified gateway equality with the live
    cluster. Every successful cycle republishes, including empty intent.
    """
    entries = {}
    for instance, state in ([(item, 'published') for item in published]
                            + [(item, 'absent') for item in absent]):
        entries[instance] = {
            'hostname': intent['entries'][instance]['hostname'],
            'observations': [{'host': host, 'state': state, 'observedAt': now}
                             for host in hostnames]}
    status = {'format': 1, 'gateways': copy.deepcopy(intent['gateways']), 'entries': entries}
    try:
        dns_status(status)
    except ValueError as error:
        raise RuntimeError('Preview DNS status refused its contract; status unpublished') from error
    manifest = {'apiVersion': 'v1', 'kind': 'ConfigMap',
                'metadata': {'name': DNS_STATUS, 'namespace': 'argocd',
                             'labels': {'cloudlab.io/owner': OWNER}},
                'data': {DNS_STATUS_KEY: json.dumps(status, sort_keys=True)}}
    ssh('VM', os.environ['VM_HOST'], binary + ' apply -f -', input=json.dumps(manifest))


def discover_cluster():
    """Live routes, gateways, and certificate readiness; failure retains DNS."""
    binary = 'k3s kubectl' if ssh(
        'VM', os.environ['VM_HOST'], 'id -u').strip() == '0' else 'sudo -n k3s kubectl'
    routes = kubectl('VM', 'get', 'httproute', '-A', binary=binary)
    private, public = [], []
    for route in routes.get('items', []):
        namespaces = {ref.get('namespace') for ref in route['spec'].get('parentRefs', [])}
        hostnames = route['spec'].get('hostnames', [])
        if namespaces == {'cloudlab-gateway-private'}:
            private.extend(hostnames)
        elif namespaces == {'cloudlab-gateway-public'}:
            public.extend(hostnames)
    service = kubectl('VM', 'get', 'service', 'cloudlab-istio', '-n', 'cloudlab-gateway-private',
                      binary=binary)
    tailnet = kubectl('VM', 'get', 'service', 'cloudlab-tailnet', '-n', 'cloudlab-gateway-private',
                      binary=binary)
    addresses = [row.get('ip') for row in tailnet.get('status', {}).get('loadBalancer', {}).get('ingress', [])
                 if row.get('ip') and ':' not in row['ip']]
    if len(addresses) != 1:
        raise RuntimeError('Private gateway has no unique ready IPv4 address')
    namespaces = kubectl('VM', 'get', 'namespace', '-l', 'cloudlab.io/owner=service-platform',
                         binary=binary)
    services = sorted(item['metadata']['name'].removeprefix('cloudlab-app-')
                      for item in namespaces.get('items', [])
                      if item.get('metadata', {}).get('name', '').startswith('cloudlab-app-'))
    certificates = {}
    for gateway in ('private', 'public'):
        certificate = kubectl('VM', 'get', 'certificate', 'cloudlab-gateway',
                              '-n', 'cloudlab-gateway-' + gateway, binary=binary)
        ready = any(condition.get('type') == 'Ready' and condition.get('status') == 'True'
                    for condition in certificate.get('status', {}).get('conditions', []))
        certificates[gateway] = {'ready': ready, 'names': certificate['spec'].get('dnsNames', [])}
    return {'private_routes': sorted(set(private)), 'public_routes': sorted(set(public)),
            'services': services,
            'cluster_gateway': service['spec']['clusterIP'], 'tailnet_gateway': addresses[0],
            'certificates': certificates, 'binary': binary}


def reconcile_dns(declared, servers, mapping, cluster, now=None):
    """Published private names with live routes converge on both resolvers.

    Preview labels come from controller intent, never from live routes: the
    controller needs published proof before it creates routes, so route-gated
    serving deadlocks activation. Desired intent is served subject only to a
    valid generation, live gateway equality, zone and label shape, no
    collision with served static names, and the preview bound; live routes
    and unrouted static names never suppress it. Every successful cycle
    republishes status observations copied from intent.
    """
    now = int(time.time()) if now is None else now
    zone = declared['zone']
    certificate = cluster['certificates']['private']
    if certificate['names'] != ['*.' + zone, 'login.' + zone.removeprefix('internal.')]:
        raise RuntimeError('Private certificate contract changed; resolvers retained')
    if not certificate['ready']:
        raise RuntimeError('Private certificate is not ready; resolvers retained')
    unapproved = sorted({entry['service'] for entry in declared.get('services', [])}
                        - set(cluster['services']))
    if unapproved:
        raise RuntimeError('Private exposures lack approved services; resolvers retained: '
                           + ', '.join(unapproved))
    routed = {name[:-len(zone) - 1] for name in cluster['private_routes']
              if name.endswith('.' + zone) and name[:-len(zone) - 1]}
    names = sorted(set(declared['names']) & routed)
    blocked = sorted(set(declared['names']) - routed)
    # Platform records are operator-declared per owning area and served as
    # listed; unrouted ones are reported for their owners instead of blocking.
    platform = sorted(declared.get('platformNames', []))
    unrouted_platform = sorted(set(platform) - routed)
    desired_names = sorted(set(names) | set(platform))
    # Preview set: desired intent labels, served with zero live routes. The
    # static gate above stays untouched: blocked names report unready but
    # never suppress the intent path or its status publication.
    intent = read_dns_intent(cluster['binary'])
    if intent['gateways'] != {'cluster': cluster['cluster_gateway'],
                              'tailnet': cluster['tailnet_gateway']}:
        raise RuntimeError('Preview DNS gateways differ from live gateways; resolvers retained')
    labels = {}
    for instance in sorted(intent['entries']):
        entry = intent['entries'][instance]
        label = (entry['hostname'][:-(len(zone) + 1)]
                 if entry['hostname'].endswith('.' + zone) else '')
        if not label or '.' in label or not tailnet_policy.dns_label(label):
            raise RuntimeError('Preview DNS intent violates its zone or label shape; resolvers retained')
        labels[instance] = label
    desired = sorted(instance for instance in labels
                     if intent['entries'][instance]['phase'] == 'desired')
    retiring = sorted(instance for instance in labels
                      if intent['entries'][instance]['phase'] == 'retiring')
    offenders = sorted({labels[instance] for instance in desired} & set(desired_names))
    if offenders:
        raise RuntimeError('Private preview names collide with served names; resolvers retained: '
                           + ', '.join(offenders))
    if len(desired) > 20:
        raise RuntimeError('Private preview names exceed their bound; resolvers retained')
    previews = sorted(labels[instance] for instance in desired)
    # Live routes are informational only: desired labels with routes, and
    # preview-shaped routes the intent never requested.
    shaped = {label for label in routed
              if '.' not in label and tailnet_policy.dns_label(label)
              and re.fullmatch(r'[a-z0-9-]{1,30}-[a-f0-9]{32}', label)}
    routed_previews = sorted({labels[instance] for instance in desired} & routed)
    unintended_routes = sorted(shaped - set(labels.values()) - set(desired_names))
    payload = {'zone': zone, 'names': desired_names, 'identity_host': certificate['names'][1],
               'cluster_gateway': cluster['cluster_gateway'],
               'tailnet_gateway': cluster['tailnet_gateway'], 'nameservers': sorted(servers),
               'previews': previews,
               'artifact': json.loads((ROOT / 'platform/connectivity/private-dns/artifact.lock.json')
                                     .read_text())['binary_sha256']}
    import yaml
    inventory = yaml.safe_load((ROOT / 'ansible/inventory.yml').read_text())
    groups = inventory['all']['children']['k3s_cluster']['children']
    hosts = {'cloudlab': ('VM', groups['k3s_servers']['hosts']['cloudlab']['wireguard_address']),
             'cloudlab-worker': ('VM2', groups['k3s_agents']['hosts']['cloudlab-worker']['wireguard_address'])}
    results = {}
    for hostname, (prefix, wireguard) in sorted(hosts.items()):
        own = dict(payload, tailnet_address=mapping[hostname], host_address=wireguard)
        try:
            live = json.loads(ssh(prefix, os.environ[prefix + '_HOST'],
                                  'cat /var/lib/cloudlab/private-dns/inputs.json'))
            current_names = sorted(live.get('names', []))
            current_previews = sorted(live.get('previews', []))
        except (RuntimeError, ValueError):
            current_names = []
            current_previews = []
        result = json.loads(ssh(prefix, os.environ[prefix + '_HOST'],
                                'python3 /var/lib/cloudlab/private-dns/dns_host.py',
                                input=json.dumps(own)))
        # The configure call proved live answers; its digest must match the
        # observed generation receipt on every host.
        observed = ssh(prefix, os.environ[prefix + '_HOST'],
                       'cat /var/lib/cloudlab/private-dns/generation').strip()
        digest = result.get('digest')
        if not result.get('dns_ready') or not digest or observed != digest:
            raise RuntimeError('Resolver drift on ' + hostname + '; retained generation kept')
        results[hostname] = {'changed': bool(result.get('changed')), 'digest': digest,
                             'withdrawn': sorted((set(current_names) | set(current_previews))
                                                - set(desired_names) - set(previews)),
                             'added': sorted((set(desired_names) | set(previews))
                                            - set(current_names) - set(current_previews))}
    # Retiring entries need both-hosts absent proof; an unproven entry stays
    # unpublished while the rest still publish. Unparseable proof output is a
    # machinery failure and blocks publication entirely.
    proven, omitted = [], []
    for instance in retiring:
        fqdn = intent['entries'][instance]['hostname']
        unproven = False
        for hostname, (prefix, _) in sorted(hosts.items()):
            try:
                observed = json.loads(ssh(prefix, os.environ[prefix + '_HOST'],
                                          'python3 /var/lib/cloudlab/private-dns/dns_host.py absent ' + fqdn))
            except ValueError:
                raise RuntimeError('Preview DNS absent proof is unreadable; status unpublished') from None
            except RuntimeError:
                unproven = True
                break
            if not isinstance(observed, dict) or fqdn not in observed.get('absent', []):
                unproven = True
                break
        (omitted if unproven else proven).append(instance)
    publish_dns_status(cluster['binary'], intent, desired, proven, sorted(hosts), now)
    return {'ready': not blocked, 'names': names, 'blocked': blocked,
            'previews': previews, 'platform': platform,
            'unrouted_platform': unrouted_platform, 'hosts': results,
            'routed': routed_previews, 'unintended_routes': unintended_routes,
            'intent': {'desired': desired, 'retiring': retiring},
            'status': {'published': desired, 'absent': proven, 'omitted': omitted}}


def cloudflare_inputs():
    """Static base plus backend, credentials, and encryption from ignored inputs."""
    for name in ('base.tfvars.json', 'backend.json', 'credentials.env', 'encryption.json'):
        if not (INPUTS / name).exists():
            raise RuntimeError('Cloudflare private inputs unavailable; refused before live plan')
    base = json.loads((INPUTS / 'base.tfvars.json').read_text())
    if set(base) != {'account_id', 'zone_id', 'tunnel_id', 'team_name', 'applications', 'routes'}:
        raise RuntimeError('Cloudflare base inputs violate their contract')
    backend = json.loads((INPUTS / 'backend.json').read_text())
    if set(backend) != {'project_id'} or not re.fullmatch(r'[1-9][0-9]*', str(backend['project_id'])):
        raise RuntimeError('Cloudflare backend requires the designated state project')
    credentials = dotenv_values(str(INPUTS / 'credentials.env'), interpolate=False)
    if not {'TF_HTTP_USERNAME', 'TF_HTTP_PASSWORD', 'CLOUDFLARE_API_TOKEN',
            'TF_VAR_dns_api_token'} <= set(credentials) or not all(
            credentials[key] for key in ('TF_HTTP_USERNAME', 'TF_HTTP_PASSWORD',
                                         'CLOUDFLARE_API_TOKEN', 'TF_VAR_dns_api_token')):
        raise RuntimeError('Cloudflare keeps backend and provider credentials separate')
    encryption = json.loads((INPUTS / 'encryption.json').read_text())
    if (set(encryption) != {'passphrase'} or not isinstance(encryption['passphrase'], str)
            or len(encryption['passphrase']) < 32):
        raise RuntimeError('Cloudflare requires its independent encryption passphrase')
    return base, backend, credentials, encryption


def tofu_environment(backend, credentials, passphrase):
    """Minimal native HTTP-backend environment with enforced state encryption."""
    result = {key: os.environ[key] for key in ('PATH', 'HOME') if key in os.environ}
    url = ('https://gitlab.com/api/v4/projects/' + str(backend['project_id'])
           + '/terraform/state/managed')
    result['TF_CLI_CONFIG_FILE'] = '/opt/runner/providers.tfrc'
    result.update(TF_HTTP_ADDRESS=url, TF_HTTP_LOCK_ADDRESS=url + '/lock',
                  TF_HTTP_UNLOCK_ADDRESS=url + '/lock', TF_HTTP_LOCK_METHOD='POST',
                  TF_HTTP_UNLOCK_METHOD='DELETE', TF_HTTP_USERNAME=credentials['TF_HTTP_USERNAME'],
                  TF_HTTP_PASSWORD=credentials['TF_HTTP_PASSWORD'], TF_HTTP_RETRY_MAX='0',
                  TF_IN_AUTOMATION='true', TF_INPUT='false',
                  CLOUDFLARE_API_TOKEN=credentials['CLOUDFLARE_API_TOKEN'],
                  TF_VAR_dns_api_token=credentials['TF_VAR_dns_api_token'])
    result['TF_ENCRYPTION'] = '''key_provider "pbkdf2" "recovery" {
  passphrase = %s
}
method "aes_gcm" "protected" {
  keys = key_provider.pbkdf2.recovery
}
state {
  method = method.aes_gcm.protected
  enforced = true
}
plan {
  method = method.aes_gcm.protected
  enforced = true
}
''' % json.dumps(passphrase)
    return result


def tofu(directory, environment, *args, timeout=600):
    result = subprocess.run(['tofu', *args], cwd=directory, env=environment,
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('Native Cloudflare operation failed; shared state retained')
    return result.stdout


def cloudflare_zone_name(credentials, zone_id):
    """Authoritative zone name for exposure validation; failure blocks planning."""
    for token in (credentials['TF_VAR_dns_api_token'], credentials['CLOUDFLARE_API_TOKEN']):
        request = urllib.request.Request(
            'https://api.cloudflare.com/client/v4/zones/' + zone_id,
            headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                document = json.load(response)
        except (urllib.error.URLError, ValueError):
            continue
        except urllib.error.HTTPError:
            continue
        if document.get('success') and document.get('result', {}).get('name'):
            return document['result']['name']
    raise RuntimeError('Cloudflare zone lookup failed; exposures retained')


def cloudflare_get(credentials, path):
    """Authoritative Cloudflare read; tries the DNS token, then management."""
    for token in (credentials['TF_VAR_dns_api_token'], credentials['CLOUDFLARE_API_TOKEN']):
        request = urllib.request.Request(
            'https://api.cloudflare.com/client/v4/' + path,
            headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                document = json.load(response)
        except urllib.error.HTTPError as error:
            if error.code in (401, 403):
                continue
            raise RuntimeError('Cloudflare lookup failed; retirement unverified') from None
        except (urllib.error.URLError, ValueError):
            continue
        if document.get('success'):
            return document.get('result')
    raise RuntimeError('Cloudflare lookup failed; retirement unverified')


def verify_retirement(base, credentials, retired_public, withdrawn_private, cluster):
    """Authoritative withdrawal proof; live route absence may lag one Argo sync."""
    proof = {}
    ingress = None
    if retired_public:
        config = cloudflare_get(credentials, 'accounts/%s/cfd_tunnel/%s/configurations'
                                % (base['account_id'], base['tunnel_id']))
        wrapped = config.get('config', {}) if isinstance(config, dict) else {}
        inner = wrapped.get('ingress', []) if isinstance(wrapped, dict) else None
        ingress = [row.get('hostname') for row in inner if isinstance(row, dict)] \
            if isinstance(inner, list) else None
        if not isinstance(ingress, list):
            raise RuntimeError('Tunnel configuration shape changed; retirement unverified')
    for hostname in sorted(retired_public):
        records = cloudflare_get(credentials, 'zones/%s/dns_records?name=%s'
                                 % (base['zone_id'], hostname))
        if not isinstance(records, list):
            raise RuntimeError('DNS lookup shape changed; retirement unverified')
        dns_gone = records == []
        tunnel_gone = hostname not in ingress
        route_gone = hostname not in cluster['public_routes']
        proof[hostname] = {'dnsWithdrawn': dns_gone, 'tunnelWithdrawn': tunnel_gone,
                           'routeAbsent': route_gone,
                           'verified': dns_gone and tunnel_gone and route_gone}
    if withdrawn_private:
        confirmed = []
        requested = set(withdrawn_private)
        for prefix in ('VM', 'VM2'):
            try:
                observed = json.loads(ssh(prefix, os.environ[prefix + '_HOST'],
                                          'python3 /var/lib/cloudlab/private-dns/dns_host.py absent '
                                          + ' '.join(sorted(withdrawn_private))))
                absent = observed['absent']
                if (not isinstance(absent, list) or
                        any(not isinstance(name, str) for name in absent) or
                        len(absent) != len(set(absent)) or not set(absent) <= requested):
                    raise ValueError
                confirmed.append(set(absent))
            except (ValueError, TypeError, KeyError):
                raise RuntimeError('Resolver retirement proof failed; retained generation kept') from None
        for hostname in sorted(withdrawn_private):
            dns_gone = all(hostname in absent for absent in confirmed)
            route_gone = hostname not in cluster['private_routes']
            proof[hostname] = {'dnsWithdrawn': dns_gone, 'routeAbsent': route_gone,
                               'verified': dns_gone and route_gone}
    return {'verified': all(row['verified'] for row in proof.values()), 'hostnames': proof}


def retired_hostnames(state_document, current):
    """Pre-apply service hostnames absent from current intent.

    Union of service Access-application domains and service DNS-record names:
    public-access services publish DNS records without an Access application,
    so domains alone would leave their retirement proof vacuous.
    """
    before = set()
    for resource in state_document.get('values', {}).get('root_module', {}).get('resources', []):
        address = resource.get('address', '')
        values = resource.get('values', {}) or {}
        if address.startswith('cloudflare_zero_trust_access_application.service_application['):
            if values.get('domain'):
                before.add(values['domain'])
        elif address.startswith('cloudflare_dns_record.service_publication['):
            if values.get('name'):
                before.add(values['name'])
    return sorted(before - set(current))


def plan_owned_scope(document, compiled_keys, retired_keys):
    """Only service-derived resources may change; shared state is untouchable."""
    for resource in document.get('resource_changes', []):
        address, actions = resource['address'], resource['change']['actions']
        if actions == ['no-op']:
            continue
        if address.startswith('cloudflare_dns_record.service_publication['):
            continue
        if address == 'cloudflare_zero_trust_tunnel_cloudflared_config.routing':
            if actions != ['update']:
                raise RuntimeError('Shared tunnel configuration replacement refused')
            continue
        match = re.fullmatch(r'cloudflare_zero_trust_access_application[.]service_application\["([^"]+)"\]',
                             address)
        if match and match[1] in compiled_keys and actions in (['create'], ['update']):
            continue
        if match and match[1] in retired_keys and actions == ['delete']:
            continue
        raise RuntimeError('Unowned Cloudflare change refused: ' + address)
    return True


def plan_digest(document):
    """Stable digest over the canonical planned change set.

    Only resource-change addresses, actions, and after-values feed the
    digest, so serialization noise in `tofu show -json` output can never
    void an approval across consecutive cycles.
    """
    changes = sorted(
        ({'address': resource['address'], 'actions': resource['change']['actions'],
          'after': resource['change'].get('after')}
         for resource in document.get('resource_changes', [])
         if resource['change']['actions'] != ['no-op']),
        key=lambda change: change['address'])
    return hashlib.sha256(json.dumps(changes, sort_keys=True).encode()).hexdigest()


def reconcile_cloudflare(config, github, cluster, *, apply_allowed=True):
    """Compile public exposures; plan always, apply only the merged binding."""
    base, backend, credentials, encryption = cloudflare_inputs()
    zone = cloudflare_zone_name(credentials, base['zone_id'])
    repo = public_slug()
    revision = github.ref(repo)
    raw = github.contents(repo, EXPOSURES_PATH, revision, limit=MAX_FILE_BYTES)
    if raw is None:
        raise RuntimeError('Public exposures unavailable; last-valid state retained')
    try:
        documents = public_exposure.validate_bundle(raw.decode(), zone)
    except Exception as error:
        raise RuntimeError('Public exposure invalid; last-valid state retained') from error
    protected = [row for row in documents
                 if row['publication'] == 'published' and row['exposure']['access'] != 'public']
    if protected and config['free_tier'] != '1':
        raise RuntimeError('Protected exposures require confirmed access-tier eligibility')
    service_token = None
    if any(row['exposure']['access'] == 'machine' for row in protected):
        service_token = fields('cloudflare-access-machine', ('SERVICE_TOKEN_ID',))['SERVICE_TOKEN_ID']
    try:
        compiled = public_exposure.compile_service_exposures(
            documents, base['routes'], human_email=config['human_email'] or None,
            identity_provider=config['identity_provider'] or None,
            service_token_id=service_token)
    except Exception as error:
        raise RuntimeError('Public exposure compilation refused') from error
    for key in compiled['applications']:
        if key in base['applications']:
            raise RuntimeError('Compiled application collides with base state; migrate explicitly')
        if any(app.get('domain') == compiled['applications'][key]['domain']
               for app in base['applications'].values()):
            raise RuntimeError('Compiled hostname already has a base application; migrate explicitly')
    # Readiness: published exposures need an approved service, a live route,
    # and a ready certificate.
    unapproved = sorted({row['service'] for row in documents
                         if row['publication'] == 'published'
                         and row['service'] not in cluster['services']})
    if unapproved:
        raise RuntimeError('Published exposures lack approved services; exposures retained: '
                           + ', '.join(unapproved))
    certificate = cluster['certificates']['public']
    if not certificate['ready']:
        raise RuntimeError('Public certificate is not ready; exposures retained')
    blocked = [key for key, value in compiled['service_exposures'].items()
               if value['exposure']['hostname'] not in cluster['public_routes']]
    if blocked:
        raise RuntimeError('Published exposures lack live routes; exposures retained: '
                           + ', '.join(sorted(blocked)))
    desired = dict(base, applications=dict(base['applications']) | compiled['applications'],
                   service_exposures=compiled['service_exposures'])
    directory = WORK / 'cloudflare'
    if directory.exists():
        shutil.rmtree(directory)
    shutil.copytree(ROOT / 'infra/cloudflare', directory,
                    ignore=shutil.ignore_patterns('tests', '.terraform*'))
    (directory / 'desired.tfvars.json').write_text(json.dumps(desired, sort_keys=True))
    os.chmod(directory / 'desired.tfvars.json', 0o600)
    environment = tofu_environment(backend, credentials, encryption['passphrase'])
    # Ephemeral work dir: the image provider mirror plus the version constraint
    # pins the provider; init records its lockfile fresh every run.
    tofu(directory, environment, 'init', '-input=false', '-reconfigure')
    planned = subprocess.run(['tofu', 'plan', '-input=false', '-detailed-exitcode',
                              '-out=plan', '-var-file=desired.tfvars.json'],
                             cwd=directory, env=environment, capture_output=True,
                             text=True, timeout=600)
    if planned.returncode not in (0, 2):
        raise RuntimeError('Native Cloudflare plan failed; shared state retained')
    document = json.loads(tofu(directory, environment, 'show', '-json', 'plan'))
    digest = plan_digest(document)
    # Retired keys are service-owned applications absent from current intent.
    retired_keys = set()
    for resource in document.get('resource_changes', []):
        match = re.fullmatch(r'cloudflare_zero_trust_access_application[.]service_application\["([^"]+)"\]',
                             resource['address'])
        if (match and match[1].startswith('service_') and match[1] not in base['applications']
                and match[1] not in compiled['applications']):
            retired_keys.add(match[1])
    plan_owned_scope(document, set(compiled['applications']), retired_keys)
    drifted = planned.returncode == 2
    published = sorted(compiled['service_exposures'])
    current = {value['exposure']['hostname'] for value in compiled['service_exposures'].values()}
    if not drifted:
        return {'ready': True, 'changed': False, 'revision': revision, 'plan': digest,
                'published': published, 'retired': []}
    # Retired hostnames are pre-apply service hostnames absent from current intent.
    retired = retired_hostnames(json.loads(tofu(directory, environment, 'show', '-json')), current)
    approval_raw = github.contents(repo, APPROVAL_PATH, revision)
    approved = False
    if approval_raw is not None:
        try:
            bound_revision, bound_plan = public_exposure.validate_approval(
                approval_raw.decode())
        except Exception as error:
            raise RuntimeError('Cloudflare approval binding invalid; exposures retained') from error
        try:
            bound_raw = github.contents(repo, EXPOSURES_PATH, bound_revision,
                                        limit=MAX_FILE_BYTES)
        except RuntimeError as error:
            raise RuntimeError('Bound exposure state unavailable; last-valid state retained') from error
        if bound_raw is not None and bound_raw == raw and bound_plan == digest:
            approved = True
    if not approved or not apply_allowed:
        return {'ready': True, 'changed': False, 'revision': revision, 'plan': digest,
                'published': published, 'retired': retired, 'drifted': True,
                'approved': approved, 'pending_review': True}
    tofu(directory, environment, 'init', '-input=false', '-reconfigure')
    applied = subprocess.run(['tofu', 'apply', '-input=false', '-auto-approve', 'plan'],
                             cwd=directory, env=environment, capture_output=True,
                             text=True, timeout=600)
    if applied.returncode:
        raise RuntimeError('Native Cloudflare apply failed; inspect shared state before retrying')
    return {'ready': True, 'changed': True, 'revision': revision, 'plan': digest,
            'published': published, 'retired': retired, 'approved': True}


def redact(status):
    """Logs carry revisions and readiness; inventory stays in the local file."""
    trimmed = copy.deepcopy(status)
    tailnet = trimmed.get('tailnet')
    if isinstance(tailnet, dict):
        trimmed['tailnet'] = {key: tailnet[key] for key in ('ready', 'changed', 'revision')
                              if key in tailnet}
        if tailnet.get('skipped'):
            trimmed['tailnet'].update(skipped=True, reason=tailnet.get('reason'))
        if tailnet.get('error'):
            trimmed['tailnet']['error'] = tailnet['error']
    dns = trimmed.get('dns')
    if isinstance(dns, dict) and 'names' in dns and isinstance(dns['names'], list):
        hosts = {host: {'changed': detail['changed'], 'digest': detail['digest'][:16],
                        'withdrawn': len(detail['withdrawn']), 'added': len(detail['added'])}
                 for host, detail in dns['hosts'].items()}
        intent = dns.get('intent', {}) or {}
        observed = dns.get('status', {}) or {}
        trimmed['dns'] = {'ready': dns['ready'], 'names': len(dns['names']),
                          'blocked': len(dns['blocked']),
                          'previews': len(dns.get('previews', [])),
                          'platform': len(dns.get('platform', [])),
                          'unrouted_platform': len(dns.get('unrouted_platform', [])),
                          'routed': len(dns.get('routed', [])),
                          'unintended_routes': len(dns.get('unintended_routes', [])),
                          'intent': {'desired': len(intent.get('desired', [])),
                                     'retiring': len(intent.get('retiring', []))},
                          'status': {'published': len(observed.get('published', [])),
                                     'absent': len(observed.get('absent', [])),
                                     'omitted': len(observed.get('omitted', []))},
                          'hosts': hosts}
    retirement = trimmed.get('retirement')
    if isinstance(retirement, dict) and isinstance(retirement.get('hostnames'), dict):
        pending = sum(not row['verified'] for row in retirement['hostnames'].values())
        trimmed['retirement'] = {'verified': retirement['verified'],
                                 'hostnames': len(retirement['hostnames']), 'pending': pending}
        if retirement.get('error'):
            trimmed['retirement']['error'] = retirement['error']
    return trimmed


def report(status):
    WORK.mkdir(parents=True, exist_ok=True)
    path = WORK / 'status.json'
    path.write_text(json.dumps(status, sort_keys=True))
    os.chmod(path, 0o600)
    print(json.dumps(redact(status), sort_keys=True), flush=True)


def once(config, github):
    """Converge tailnet and DNS; plan Cloudflare, applying only when bound."""
    status, failed = {}, False
    try:
        tailnet = reconcile_tailnet(config, github)
        status['tailnet'] = {key: tailnet[key] for key in tailnet if key != 'declared'}
    except RuntimeError as error:
        failed = True
        status['tailnet'] = {'ready': False, 'error': str(error)}
        tailnet = None
    try:
        cluster = discover_cluster()
        status['cluster'] = {'ready': True}
    except RuntimeError as error:
        failed = True
        status['cluster'] = {'ready': False, 'error': str(error)}
        cluster = None
    if tailnet and cluster and not tailnet.get('skipped'):
        try:
            ensure_resolver_scripts()
            status['dns'] = reconcile_dns(tailnet['declared'], tailnet['servers'],
                                           tailnet['mapping'], cluster)
            if status['dns']['blocked']:
                failed = True
        except RuntimeError as error:
            failed = True
            status['dns'] = {'ready': False, 'error': str(error)}
    elif tailnet and tailnet.get('skipped'):
        status['dns'] = {'ready': False, 'skipped': True, 'reason': 'no tailnet declaration'}
    else:
        status['dns'] = {'ready': False, 'skipped': True}
        failed = True
    if cluster:
        try:
            status['cloudflare'] = reconcile_cloudflare(config, github, cluster)
        except RuntimeError as error:
            failed = True
            status['cloudflare'] = {'ready': False, 'error': str(error)}
    else:
        status['cloudflare'] = {'ready': False, 'skipped': True}
        failed = True
    retired_public = []
    withdrawn_private = set()
    if status.get('cloudflare', {}).get('changed'):
        retired_public = status['cloudflare'].get('retired', [])
    if isinstance(status.get('dns'), dict) and isinstance(status['dns'].get('hosts'), dict):
        zone = (tailnet or {}).get('zone', '')
        for detail in status['dns']['hosts'].values():
            withdrawn_private.update(label + '.' + zone for label in detail.get('withdrawn', []))
    if (retired_public or withdrawn_private) and cluster:
        try:
            ensure_resolver_scripts()
            base = credentials = None
            if retired_public:
                base, _, credentials, _ = cloudflare_inputs()
                base = {'account_id': base['account_id'], 'zone_id': base['zone_id'],
                        'tunnel_id': base['tunnel_id']}
            requested = set(retired_public) | withdrawn_private
            if set(retired_public) & withdrawn_private:
                raise RuntimeError('Retirement proof failed; retained generation kept')
            retirement = verify_retirement(base, credentials, retired_public,
                                           withdrawn_private, discover_cluster())
            rows = retirement.get('hostnames') if isinstance(retirement, dict) else None
            if (not isinstance(rows, dict) or set(rows) != requested or
                    any(not isinstance(row, dict) or type(row.get('verified')) is not bool
                        for row in rows.values()) or
                    type(retirement.get('verified')) is not bool or
                    retirement['verified'] != all(row['verified'] for row in rows.values())):
                raise RuntimeError('Retirement proof failed; retained generation kept')
            status['retirement'] = retirement
            if not retirement['verified']:
                failed = True
        except RuntimeError as error:
            failed = True
            status['retirement'] = {'verified': False, 'error': str(error)}
    elif not cluster:
        status['retirement'] = {'verified': False, 'skipped': True}
        failed = True
    else:
        status['retirement'] = {'verified': True, 'hostnames': {}}
    status['ok'] = not failed
    report(status)
    return status


def verify(config, github):
    """Read-only proof that live state matches accepted Git intent; never mutates."""
    proof, failed = {}, False
    try:
        repo = repository_slug(config['private_repository'])
        revision = github.ref(repo)
        raw = github.contents(repo, POLICY_PATH, revision)
        if raw is None:
            proof['tailnet'] = {'verified': False, 'reason': 'no tailnet declaration'}
            failed = True
            declared = None
        else:
            import yaml
            try:
                declared = tailnet_policy.validate_policy(yaml.safe_load(raw))
            except Exception as error:
                raise RuntimeError('Tailnet declaration invalid') from error
            if declared['administrator'] != config['administrator']:
                raise RuntimeError('Tailnet declaration administrator differs from the approved login')
            api = TailnetAPI('tailscale-policy')
            mapping, users = tailnet_addresses(api, declared['resolvers'])
            servers = [mapping[name] for name in declared['resolvers']]
            zone = declared['zone']
            identity_host = 'login.' + zone.removeprefix('internal.')
            current, _ = api.request('GET', 'tailnet/-/acl')
            live_dns = api.request('GET', 'tailnet/-/dns/split-dns')[0]
            desired = tailnet_policy.candidate(
                current, declared, servers, users - {declared['administrator']})
            desired_dns = tailnet_policy.split_dns(
                tailnet_policy.split_dns(live_dns, zone, servers), identity_host, servers)
            proof['tailnet'] = {
                'verified': current == desired and all(
                    live_dns.get(name) == desired_dns[name] for name in (zone, identity_host)),
                'revision': revision, 'aclConverged': current == desired,
                'splitDnsConverged': all(live_dns.get(name) == desired_dns[name]
                                         for name in (zone, identity_host)),
                'declaredTests': len(declared['accessTests'])}
            if not proof['tailnet']['verified']:
                failed = True
    except RuntimeError as error:
        failed = True
        proof['tailnet'] = {'verified': False, 'error': str(error)}
        declared = None
    try:
        cluster = discover_cluster()
        proof['cluster'] = {'ready': True, 'privateRoutes': len(cluster['private_routes']),
                            'publicRoutes': len(cluster['public_routes'])}
    except RuntimeError as error:
        failed = True
        proof['cluster'] = {'ready': False, 'error': str(error)}
        cluster = None
    if declared is not None and cluster is not None:
        try:
            digests = {}
            for prefix in ('VM', 'VM2'):
                observed = json.loads(ssh(prefix, os.environ[prefix + '_HOST'],
                                          'python3 /var/lib/cloudlab/private-dns/dns_host.py check'))
                if not observed.get('dns_ready'):
                    raise RuntimeError('Resolver on ' + prefix + ' is not ready')
                digests[prefix] = observed['digest']
            proof['dns'] = {'verified': digests['VM'] == digests['VM2'],
                            'generationsMatch': digests['VM'] == digests['VM2']}
            if not proof['dns']['verified']:
                failed = True
        except (RuntimeError, ValueError):
            failed = True
            proof['dns'] = {'verified': False,
                            'error': 'Resolver generations differ or are unreadable'}
    else:
        proof['dns'] = {'verified': False, 'skipped': True}
        failed = True
    if cluster is not None:
        try:
            planned = reconcile_cloudflare(config, github, cluster, apply_allowed=False)
            drifted = bool(planned.get('drifted'))
            proof['cloudflare'] = {'inspected': True, 'verified': not drifted,
                                   'revision': planned['revision'], 'plan': planned['plan'],
                                   'drifted': drifted,
                                   'approved': bool(planned.get('approved', False))}
            if drifted:
                failed = True
        except RuntimeError as error:
            failed = True
            proof['cloudflare'] = {'verified': False, 'error': str(error)}
    else:
        proof['cloudflare'] = {'verified': False, 'skipped': True}
        failed = True
    proof['verified'] = not failed
    report(proof)
    return proof


def main(argv):
    if argv[:1] not in (['once'], ['loop'], ['verify']):
        raise SystemExit('Connectivity reconciler requires once, loop, or verify')
    if '--review' in argv:
        raise SystemExit('The review flag is retired; approval comes from the merged Git binding')
    os.umask(0o077)
    WORK.mkdir(parents=True, exist_ok=True)
    with (WORK / 'lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise SystemExit('Another connectivity reconciliation holds the lock')
        config = configuration()
        for name in ('VM_HOST', 'VM_USER', 'VM_PASSWORD', 'VM2_HOST', 'VM2_USER', 'VM2_PASSWORD'):
            if not os.environ.get(name):
                raise SystemExit('Missing lab connection input: ' + name)
        github = GitHub(config['github_token'])
        if argv[0] == 'once':
            status = once(config, github)
            raise SystemExit(0 if status['ok'] else 1)
        if argv[0] == 'verify':
            proof = verify(config, github)
            raise SystemExit(0 if proof['verified'] else 1)
        while True:
            try:
                once(config, github)
            except RuntimeError as error:
                report({'ok': False, 'error': str(error)})
            except Exception:
                report({'ok': False, 'error': 'Connectivity reconciliation failed; state retained'})
            time.sleep(config['interval'])


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except RuntimeError as error:
        raise SystemExit(str(error)) from None

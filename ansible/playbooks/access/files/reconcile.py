"""Control-machine connectivity reconciler: tailnet, private DNS, public DNS.

Reads accepted Git revisions only. Tailnet and private DNS converge
automatically; Cloudflare plans automatically but applies only with an explicit
reviewed plan hash. Invalid or unreachable sources retain last-valid state and
report blocked; they never delete, grant, or publish.
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

from dotenv import dotenv_values

import policy as tailnet_policy
import exposure as public_exposure
from control import API as TailnetAPI
from verify_access import ssh
from playbooks.secrets.files.vault import fields

ROOT = Path(__file__).resolve().parents[4]
WORK = Path('/infra-work/connectivity')
INPUTS = Path('/inputs/cloudflare')
POLICY_PATH = 'platform/access/policy.yaml'
MAX_FILE_BYTES = 65536


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

    def contents(self, repo, path, ref):
        document = self.request('repos/' + repo + '/contents/' + path + '?ref=' + ref)
        if document is None:
            return None
        if (not isinstance(document, dict) or document.get('type') != 'file'
                or document.get('encoding') != 'base64'
                or type(document.get('size')) is not int
                or not 0 < document['size'] <= 4096
                or not isinstance(document.get('content'), str)):
            raise RuntimeError('Git declaration requires a bounded regular file')
        raw = base64.b64decode(document['content'].replace('\r', '').replace('\n', ''), validate=True)
        if len(raw) != document['size']:
            raise RuntimeError('Git declaration size changed during transfer')
        return raw

    def tree(self, repo, ref):
        document = self.request('repos/' + repo + '/git/trees/' + ref + '?recursive=1',
                                limit=1048576)
        if not document or document.get('truncated'):
            raise RuntimeError('Git source snapshot is incomplete; refused')
        entries = document.get('tree', [])
        if len(entries) > 20000:
            raise RuntimeError('Git source snapshot exceeds its bound')
        return [row['path'] for row in entries if row.get('type') == 'blob']


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
            'certificates': certificates}


def reconcile_dns(declared, servers, mapping, cluster):
    """Published private names with live routes converge on both resolvers."""
    zone = declared['zone']
    certificate = cluster['certificates']['private']
    if certificate['names'] != ['*.' + zone, 'login.' + zone.removeprefix('internal.')]:
        raise RuntimeError('Private certificate contract changed; resolvers retained')
    if not certificate['ready']:
        raise RuntimeError('Private certificate is not ready; resolvers retained')
    routed = {name[:-len(zone) - 1] for name in cluster['private_routes']
              if name.endswith('.' + zone) and name[:-len(zone) - 1]}
    names = sorted(set(declared['names']) & routed)
    blocked = sorted(set(declared['names']) - routed)
    # Platform records are operator-declared per owning area and served as
    # listed; unrouted ones are reported for their owners instead of blocking.
    platform = sorted(declared.get('platformNames', []))
    unrouted_platform = sorted(set(platform) - routed)
    desired_names = sorted(set(names) | set(platform))
    payload = {'zone': zone, 'names': desired_names, 'identity_host': certificate['names'][1],
               'cluster_gateway': cluster['cluster_gateway'],
               'tailnet_gateway': cluster['tailnet_gateway'], 'nameservers': sorted(servers),
               'artifact': json.loads((ROOT / 'platform/connectivity/private-dns/artifact.lock.json')
                                     .read_text())['sha256']}
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
        except (RuntimeError, ValueError):
            current_names = []
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
                             'withdrawn': sorted(set(current_names) - set(desired_names)),
                             'added': sorted(set(desired_names) - set(current_names))}
    return {'ready': not blocked, 'names': names, 'blocked': blocked,
            'platform': platform, 'unrouted_platform': unrouted_platform,
            'hosts': results}


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


def reconcile_cloudflare(config, github, cluster, *, review=None):
    """Compile public exposures; plan always, apply only the reviewed plan."""
    base, backend, credentials, encryption = cloudflare_inputs()
    zone = cloudflare_zone_name(credentials, base['zone_id'])
    repo = public_slug()
    revision = github.ref(repo)
    paths = [path for path in github.tree(repo, revision)
             if re.fullmatch(r'services/[a-z][a-z0-9-]+/exposure[.]yaml', path)]
    if len(paths) > 20:
        raise RuntimeError('Public exposures exceed their bound')
    documents = []
    exposures = WORK / 'exposures'
    exposures.mkdir(parents=True, exist_ok=True)
    for stale in exposures.iterdir():
        if stale.name != revision:
            shutil.rmtree(stale, ignore_errors=True)
    with_dir = exposures / revision
    if with_dir.exists():
        shutil.rmtree(with_dir)
    for path in sorted(paths):
        raw = github.contents(repo, path, revision)
        if raw is None:
            raise RuntimeError('Public exposure snapshot is incomplete; refused')
        target = with_dir / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        try:
            documents.append(public_exposure.validate_file(str(target), zone))
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
    digest = hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest()
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
    if not drifted:
        return {'ready': True, 'changed': False, 'revision': revision, 'plan': digest,
                'published': sorted(compiled['service_exposures'])}
    if review is None:
        return {'ready': True, 'changed': False, 'revision': revision, 'plan': digest,
                'published': sorted(compiled['service_exposures']), 'drifted': True,
                'pending_review': True}
    if review != digest:
        raise RuntimeError('Apply requires the exact reviewed plan')
    tofu(directory, environment, 'init', '-input=false', '-reconfigure')
    applied = subprocess.run(['tofu', 'apply', '-input=false', '-auto-approve', 'plan'],
                             cwd=directory, env=environment, capture_output=True,
                             text=True, timeout=600)
    if applied.returncode:
        raise RuntimeError('Native Cloudflare apply failed; inspect shared state before retrying')
    return {'ready': True, 'changed': True, 'revision': revision, 'plan': digest,
            'published': sorted(compiled['service_exposures'])}


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
        trimmed['dns'] = {'ready': dns['ready'], 'names': len(dns['names']),
                          'blocked': len(dns['blocked']),
                          'platform': len(dns.get('platform', [])),
                          'unrouted_platform': len(dns.get('unrouted_platform', [])),
                          'hosts': hosts}
    return trimmed


def report(status):
    WORK.mkdir(parents=True, exist_ok=True)
    path = WORK / 'status.json'
    path.write_text(json.dumps(status, sort_keys=True))
    os.chmod(path, 0o600)
    print(json.dumps(redact(status), sort_keys=True), flush=True)


def once(config, github, *, review=None):
    """Converge tailnet and DNS; plan Cloudflare, applying only when reviewed."""
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
            status['cloudflare'] = reconcile_cloudflare(config, github, cluster, review=review)
        except RuntimeError as error:
            failed = True
            status['cloudflare'] = {'ready': False, 'error': str(error)}
    else:
        status['cloudflare'] = {'ready': False, 'skipped': True}
        failed = True
    status['ok'] = not failed
    report(status)
    return status


def main(argv):
    if argv[:1] not in (['once'], ['loop']):
        raise SystemExit('Connectivity reconciler requires once or loop')
    review = None
    if '--review' in argv:
        try:
            review = argv[argv.index('--review') + 1]
        except IndexError:
            raise SystemExit('Apply requires the exact reviewed plan hash') from None
        if not re.fullmatch('[a-f0-9]{64}', review or ''):
            raise SystemExit('Apply requires the exact reviewed plan hash')
    if argv[0] == 'loop' and review is not None:
        raise SystemExit('Standing reconciliation never carries a standing apply review')
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
            status = once(config, github, review=review)
            raise SystemExit(0 if status['ok'] else 1)
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

"""Concrete Compose consumers of existing field owners, with read-before-write gates."""
import json
import os
from pathlib import Path
import shlex
import sys
import urllib.error
import urllib.request
import yaml

from playbooks.infrastructure.files.command import Client
from playbooks.services.files import native
from playbooks.services.files.contract import ROOT
from playbooks.services.files.gitops import resources
from playbooks.keycloak.files.health import NoRedirect


class Owners:
    def __init__(self, bundle):
        if set(bundle) != {'definition', 'approval', 'platformRepository', 'platformRevision', 'origin', 'application'}:
            raise ValueError('Service operation requires its complete reviewed private bundle')
        platform = yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())['repository']
        origin = json.loads((ROOT / 'platform/connectivity/access/contract.json').read_text())['cloudflareOrigin']
        if bundle['platformRepository'] != platform or bundle['origin'] != origin:
            raise ValueError('Service operation cannot select a different platform repository or shared gateway origin')
        self.bundle = bundle
        self.definition, self.approval = bundle['definition'], bundle['approval']
        resources(self.definition, self.approval, bundle['platformRepository'], bundle['platformRevision'])
        self.client = None
        self.private_denial_verified = False

    def require_private_inputs(self, definition):
        if definition != self.definition:
            raise ValueError('Operation differs from the reviewed service bundle')
        from dotenv import dotenv_values
        values = dotenv_values(ROOT / '.env', interpolate=False)
        for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD'):
            if not values.get(key): raise ValueError('Service operations require the existing VM access inputs')
            os.environ[key] = values[key]
        os.environ['VM_PORT'] = values.get('VM_PORT') or '22'
        os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
        os.environ['TAILSCALE_ADMIN_LOGIN'] = values.get('TAILSCALE_ADMIN_LOGIN') or ''
        from playbooks.services.files.inputs import catalog
        approved = [row for row in catalog(required=True)['catalog']
                    if row['definition'] == definition and row['approval'] == self.approval]
        if len(approved) != 1:
            raise ValueError('Service operation requires its exact current administrator catalog approval')
        if definition['exposure']['class'] == 'public':
            self.client = Client('cloudflare')

    def read(self, action):
        from playbooks.access.files.preflight import ssh
        # Inspect versioned code through stdin; no manual host configuration.
        source = (ROOT / 'ansible/playbooks/services/files/remote.py').read_text()
        request = json.dumps({'action': action, 'definition': self.definition, 'approval': self.approval})
        code = "import sys;sys.path.insert(0,'/opt/cloudlab');" + source
        output = ssh('VM', os.environ['VM_HOST'], 'python3 -c ' + shlex.quote(code), input=request,
                     timeout=660 if action in ('fixture-data', 'fixture-volume') else 90)
        result = json.loads(output)
        if result.get('ready') is not True:
            raise RuntimeError('Service owner readiness was not confirmed')
        return result

    def current_exposure(self, definition):
        if not self.client: return None
        key = 'service_' + definition['name'].replace('-', '_')
        value = self.client.desired.get('service_exposures', {}).get(key)
        return value['exposure'] if value else None

    def identity_ready(self, definition): self.read('identity')
    def data_ready(self, definition): self.read('data')
    def backend_ready(self, definition): self.read('backend')
    def tls_ready(self, definition): self.read('tls')

    def protection_apply(self, definition):
        # Privileged protection remains with the existing platform owner. An
        # onboarding request cannot invent policy selectors or identity providers.
        self.protection_verified(definition)

    def protection_verified(self, definition):
        exposure = definition['exposure']
        private = [e for e in [exposure] + definition.get('additionalExposures', []) if e['class'] == 'private']
        if private:
            self.private_protection()
        if exposure['class'] == 'private':
            self.read('tls')
            return
        if exposure['class'] == 'none': return
        if exposure['access'] == 'public':
            if self.bundle['application'] is not None:
                raise ValueError('Public exposure must not reuse unrelated Access protection')
            if self.approval.get('chartPath') == 'apps/notes': self.read('api-protection')
            return
        selected = self.client.desired['applications'].get(self.bundle['application'])
        if not selected or selected['domain'] != exposure['hostname']:
            raise RuntimeError('Platform must provision the exact approved Access application before publication')
        from playbooks.access.files.cloudflare import API
        api = API(self.client.env['CLOUDFLARE_API_TOKEN'])
        address = 'cloudflare_zero_trust_access_application.application[' + json.dumps(self.bundle['application']) + ']'
        inventory = self.client.inventory[address]
        actual = api.request('GET', 'accounts/' + self.client.desired['account_id'] + '/access/apps/' + inventory['id'])
        if actual.get('aud') != inventory['aud'] or actual.get('domain') != exposure['hostname'] or not actual.get('policies'):
            raise RuntimeError('Access protection identity or policy is not verified')
        policies = api.request('GET', 'accounts/' + self.client.desired['account_id'] + '/access/apps/' + inventory['id'] + '/policies')
        observed = {policy['id']: policy for policy in policies}
        if set(observed) != set(inventory['policies']):
            raise RuntimeError('Access policy identities differ from the platform inventory')
        for policy in selected['policies'].values():
            if any(observed[policy['id']].get(field, [] if field in ('include', 'exclude', 'require') else None) != policy[field]
                   for field in ('decision', 'include', 'exclude', 'require') if field in policy):
                raise RuntimeError('Access policy decisions or selectors differ from approved protection')

    def private_protection(self):
        sys.path.insert(0, str(ROOT / 'ansible/playbooks/tailscale/files'))
        from control import API
        from playbooks.access.files.tailnet import candidate
        actual, _ = API('tailscale-policy').request('GET', 'tailnet/-/acl')
        if candidate(actual, os.environ['TAILSCALE_ADMIN_LOGIN']) != actual:
            raise RuntimeError('Existing private service protection is not converged')
        if not self.private_denial_verified:
            peer = self.read('private-boundary')['privatePeer']
            from playbooks.access.files.tailnet_probe import client, tailnet_connect
            with client() as (control_socket, status):
                peers = {ip for row in (status.get('Peer') or {}).values() for ip in row.get('TailscaleIPs', [])}
                if tailnet_connect(control_socket, peer, 443, peers):
                    raise RuntimeError('Denied tailnet identity reached the private gateway')
            self.private_denial_verified = True

    def stage(self, operation):
        desired = native.stage(self.definition, operation, self.bundle['origin'], self.bundle['application'])
        self.client = Client('cloudflare')
        return desired

    def routing_apply(self, definition):
        if definition['exposure']['class'] == 'public': self.stage('route')

    def routing_verified(self, definition):
        if definition['exposure']['class'] != 'public':
            self.read('tls')
            return
        from playbooks.access.files.cloudflare import API
        desired = self.client.desired
        actual = API(self.client.env['CLOUDFLARE_API_TOKEN']).request('GET',
            'accounts/' + desired['account_id'] + '/cfd_tunnel/' + desired['tunnel_id'] + '/configurations')
        rows = [row for row in actual['config']['ingress'] if row.get('hostname') == definition['exposure']['hostname']]
        if len(rows) != 1 or rows[0]['service'] != self.bundle['origin']:
            raise RuntimeError('Tunnel route is not observed at its approved origin')
        request = rows[0].get('originRequest', rows[0].get('origin_request', {}))
        hostname = definition['exposure']['hostname']
        if (request.get('originServerName', request.get('origin_server_name')) != hostname or
                request.get('httpHostHeader', request.get('http_host_header')) != hostname):
            raise RuntimeError('Observed tunnel route does not preserve approved TLS SNI and hostname')
        if request.get('noTLSVerify', request.get('no_tls_verify', False)) is not False:
            raise RuntimeError('Tunnel origin disables TLS verification')
        if definition['exposure']['access'] != 'public':
            selected = self.client.inventory['cloudflare_zero_trust_access_application.application[' + json.dumps(self.bundle['application']) + ']']
            access = request.get('access', {})
            if access.get('required') is not True or access.get('audTag', access.get('aud_tag')) != [selected['aud']]:
                raise RuntimeError('Tunnel does not enforce the approved Access audience')

    def dns_publish(self, definition):
        if definition['exposure']['class'] == 'public': self.stage('publish')
        from playbooks.services.files.publication import set_intent, private_dns
        private = [e for e in [definition['exposure']] + definition.get('additionalExposures', []) if e['class'] == 'private']
        if private:
            set_intent(definition, 'published')
            for exposure in private: private_dns(dict(definition, exposure=exposure), published=True)

    def reachability_verified(self, definition):
        url = 'https://' + definition['exposure']['hostname'] + definition['exposure']['path']
        opener = urllib.request.build_opener(NoRedirect())
        try:
            with opener.open(urllib.request.Request(url, headers={'User-Agent': 'CloudLab-Service-Proof/1.0'}), timeout=15) as response:
                status = response.status
        except urllib.error.HTTPError as error:
            status = error.code
        if definition['exposure']['access'] == 'public' and status not in (200, 401):
            raise RuntimeError('Published service is unavailable')
        if definition['exposure']['class'] == 'private' and status not in (200, 401, 403):
            raise RuntimeError('Private publication did not reach its authenticated network path')
        if definition['exposure']['class'] == 'public' and definition['exposure']['access'] != 'public' and status not in (302, 401, 403):
            raise RuntimeError('Anonymous client is not denied by published protection')

    def dns_withdraw(self, definition):
        if definition['exposure']['class'] == 'public': self.stage('withdraw-dns')
        from playbooks.services.files.publication import set_intent, private_dns
        private = [e for e in [definition['exposure']] + definition.get('additionalExposures', []) if e['class'] == 'private']
        if private:
            set_intent(definition, 'retired')
            for exposure in private: private_dns(dict(definition, exposure=exposure), published=False)

    def routing_withdraw(self, definition):
        if definition['exposure']['class'] == 'public': self.stage('withdraw-route')
        if definition['exposure']['class'] != 'none':
            self.retire_catalog()
            self.read('retire-route')

    def unreachable_verified(self, definition):
        if definition['exposure']['class'] == 'none': return
        if definition['exposure']['class'] == 'private':
            self.read('route-absent')
            return
        from playbooks.access.files.cloudflare import API
        desired = self.client.desired
        actual = API(self.client.env['CLOUDFLARE_API_TOKEN']).request('GET',
            'accounts/' + desired['account_id'] + '/cfd_tunnel/' + desired['tunnel_id'] + '/configurations')
        if any(row.get('hostname') == definition['exposure']['hostname'] for row in actual['config']['ingress']):
            raise RuntimeError('Tunnel still exposes the retired service')
        self.read('route-absent')

    def protection_retire(self, definition):
        # Retain Access resources. Shared protection is never deleted by a service.
        self.unreachable_verified(definition)

    def identity_retire(self, definition):
        if definition['oidc']['enabled']:
            from playbooks.keycloak.files.lifecycle import local
            local({'realm': definition['oidc']['realm'], 'client_id': definition['oidc']['client']})

    def workload_retire(self, definition):
        self.retire_catalog()
        self.read('retire-workload')

    def retire_catalog(self):
        from playbooks.services.files.publication import set_intent
        from playbooks.access.files.preflight import ssh
        set_intent(self.definition, 'retired')
        # Argo reads the protected Git change directly; no local catalog apply.
        self.read('retired-intent')

    def data_retained(self, definition):
        self.read('data')

"""Outside HTTPS, private DNS, tailnet identity and bounded replica failure proof."""
import concurrent.futures
import http.client
import ipaddress
import json
import os
from pathlib import Path
import socket
import sys
import time
from functools import partial
from urllib.parse import urlsplit

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'automation/tailscale'))
from control import API
from verify_access import ssh
from automation.credentials.vault import fields
from automation.connectivity.contract import host_rules, private_names
from automation.connectivity.dns_wire import absent_answer, private_answer, query
from automation.connectivity.traffic import denied, https as request_https, success
from automation.connectivity.cluster_fixture import PROOF_PATH
from automation.connectivity.tailnet_probe import verify as denied_tailnet
from automation.connectivity.human import retained as human_evidence
from automation.connectivity.checkpoint import transaction

https = partial(request_https, path=PROOF_PATH)


def remote(action, **payload):
    result = json.loads(ssh('VM', os.environ['VM_HOST'],
        'python3 /var/lib/cloudlab/connectivity/cluster_fixture.py',
        input=json.dumps(dict(payload, action=action)), timeout=600))
    if action == 'fail-one' and 'crash_target' in result:
        for prefix in ('VM', 'VM2'):
            if ssh(prefix, os.environ[prefix + '_HOST'], 'hostname').strip() == result['node']:
                return json.loads(ssh(prefix, os.environ[prefix + '_HOST'],
                    'python3 /var/lib/cloudlab/connectivity/proxy_failure.py',
                    input=json.dumps(result['crash_target']), timeout=45))
        raise RuntimeError('Proxy crash target is not on either declared VM')
    return result


def retry(function, label, timeout=120):
    deadline = time.monotonic() + timeout
    while True:
        try:
            result = function()
            if result:
                return result
        except (OSError, RuntimeError):
            pass
        if time.monotonic() > deadline:
            raise RuntimeError('Access proof failed: ' + label)
        time.sleep(2)


def disruption(component, probe):
    """Crash one proxy container or replace one Pod; probe with fresh TCP/TLS."""
    if not probe():
        raise RuntimeError('Failure fixture lacks a successful baseline')
    before = remote('snapshot')
    limit, observe = 30, 90
    start = last_success = time.monotonic()
    errors = successes = 0
    longest_gap = 0.0
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        failure = executor.submit(remote, 'fail-one', component=component)
        failure_at = None
        while failure_at is None or time.monotonic() - failure_at < observe:
            if failure_at is None and failure.done():
                deletion = failure.result()
                failure_at = time.monotonic()
            if failure_at is None and time.monotonic() - start > 120:
                raise RuntimeError('Disposable failure injection did not finish within 120 seconds')
            try:
                ok = probe()
            except (OSError, RuntimeError, http.client.HTTPException):
                ok = False
            now = time.monotonic()
            # A late successful response must not erase an excessive outage.
            if now - last_success > limit:
                raise RuntimeError('New requests exceeded the declared 30-second failure recovery limit')
            if ok:
                longest_gap = max(longest_gap, now - last_success)
                last_success = now
                successes += 1
            else:
                errors += 1
            time.sleep(1)
    longest_gap = max(longest_gap, time.monotonic() - last_success)
    if longest_gap > limit:
        raise RuntimeError('New requests exceeded the declared 30-second failure recovery limit')
    after = retry(lambda: remote('snapshot'), 'replicas restored after failure', timeout=300)
    if 'crashed_container' in deletion:
        old = next((p for p in before[component] if p['uid'] == deletion['retained_pod_uid']), None)
        new = next((p for p in after[component] if p['uid'] == deletion['retained_pod_uid']), None)
        if not old or not new or deletion['crashed_container'] not in old['containers'] or deletion['crashed_container'] in new['containers']:
            raise RuntimeError('Crash test did not restart the selected container with its original Pod identity')
    elif deletion['deleted_uid'] not in {p['uid'] for p in before[component]} or deletion['deleted_uid'] in {p['uid'] for p in after[component]}:
        raise RuntimeError('Failure test did not replace its selected disposable Pod')
    if successes < 10:
        raise RuntimeError('Too few new successful requests during disruption observation')
    return {'new_requests_ok': successes, 'request_errors': errors, 'longest_success_gap_seconds': round(longest_gap, 2),
            'limit_seconds': limit, 'observation_seconds': observe, 'replicas_restored': True,
            'failure_mode': 'container-sigkill' if 'crashed_container' in deletion else 'pod-replacement'}


def _run(*, failures=True, keep=False):
    from automation.connectivity.external import run as reconcile_external
    reconcile_external()
    runtime = remote('runtime')
    rules = host_rules(json.loads(os.environ['CLOUDFLARE_ACCESS_HOSTS']), runtime['zone'])
    protocol = 'login.' + runtime['zone']
    if os.environ.get('LAB_IDENTITY_ENABLED') == '1':
        if not any(rule == {'hostname': protocol, 'access': 'public'} for rule in rules):
            raise RuntimeError('Identity protocol host must remain public without circular Access')
        rules = [rule for rule in rules if rule['hostname'] != protocol]
    private = private_names(json.loads(os.environ['PRIVATE_ACCESS_HOSTS']))
    categories = {kind: [r['hostname'] for r in rules if r['access'] == kind] for kind in ('public', 'human', 'machine')}
    if any(not names for names in categories.values()):
        raise RuntimeError('Acceptance requires public, human and machine hostnames')
    api_url = urlsplit(runtime['api_url'])
    if api_url.scheme != 'https' or not api_url.hostname or not api_url.hostname.endswith('.ts.net'):
        raise RuntimeError('API proxy does not advertise its expected HTTPS identity')
    api_service, _ = API('tailscale-operator').request('GET', 'tailnet/-/services/svc:cloudlab-api')
    api_address = next(a for a in api_service['addrs'] if ipaddress.ip_address(a).version == 4)
    nameservers = []
    for prefix in ('VM', 'VM2'):
        nameservers.append(ssh(prefix, os.environ[prefix + '_HOST'], 'tailscale ip -4').strip())
    machine = fields('cloudflare-access-machine', ('CLIENT_ID', 'CLIENT_SECRET'))
    headers = {'CF-Access-Client-Id': machine['CLIENT_ID'], 'CF-Access-Client-Secret': machine['CLIENT_SECRET']}
    public = json.loads(os.environ['CLOUDFLARE_ACCESS_HOSTS'])
    if os.environ.get('LAB_IDENTITY_ENABLED') == '1':
        public = [rule for rule in public if rule['name'] != 'login']
    payload = {'public': public, 'private': private,
               'smoke_image': yaml.safe_load((ROOT / 'ansible/group_vars/all/verification.yml').read_text())['smoke_image']}
    output = {}
    try:
        remote('prepare', **payload)
        if runtime.get('identity_server_present'):
            from automation.identity.health import check, proxy_privacy
            output['identity_protocols'] = {realm: check('https://' + protocol + '/realms/' + realm)
                                             for realm in ('platform', 'applications')}
            output['identity_gateway'] = proxy_privacy(protocol)
        remote('snapshot')
        identities = remote('identities')
        with transaction() as receipts:
            previous = receipts.load('acceptance')
        if previous and previous.get('identities') != identities:
            raise RuntimeError('Persisted proxy identity changed since accepted proof')
        for hostname in categories['public']:
            response = retry(lambda: (r if success(r := https(hostname)) else False), 'outside public HTTPS')
            if not response['public_peer'] or not response['headers'].get('cf-ray'):
                raise RuntimeError('Public proof did not traverse the outside Cloudflare edge')
        for hostname in categories['machine']:
            retry(lambda: success(https(hostname, headers=headers)), 'machine service-token authentication')
            invalid = dict(headers, **{'CF-Access-Client-Secret': 'invalid-disposable-proof'})
            if not denied(https(hostname)) or not denied(https(hostname, headers=invalid)):
                raise RuntimeError('Machine Access accepted an unauthorized caller')
        for hostname in categories['human']:
            if not denied(https(hostname)) or not denied(https(hostname, headers=headers)):
                raise RuntimeError('Human Access accepted an anonymous caller or machine identity')
        public_host = categories['public'][0]
        private_host = private[0] + '.' + runtime['private']['zone']
        for hostname in ['unknown-cloudlab-proof.' + runtime['zone'], private_host]:
            response = https(public_host, headers={'Host': hostname})
            edge_unknown = response['status'] == 530 and response['headers'].get('cf-ray') and b'mesh-ok' not in response['body']
            if not denied(response) and not edge_unknown:
                raise RuntimeError('Unknown or private hostname leaked through the public edge')
        for prefix in ('VM', 'VM2'):
            for port in (80, 443, 6443):
                try:
                    connection = socket.create_connection((os.environ[prefix + '_HOST'], port), timeout=3)
                except (ConnectionRefusedError, TimeoutError):
                    continue
                else:
                    connection.close()
                    raise RuntimeError('A public VM ingress or Kubernetes API port is reachable')
        if query('1.1.1.1', private_host)['addresses']:
            raise RuntimeError('Private hostname has a public DNS address')
        output.update(outside_public_https=True, machine_authenticated=True, machine_unauthorized_denied=True,
                      human_anonymous_and_machine_denied=True, unknown_and_private_public_routes_denied=True,
                      public_vm_ingress_and_api_ports_closed=True)
        for server in nameservers:
            for tcp in (False, True):
                private_answer(server, private_host, runtime['private']['tailnet_gateway'], tcp=tcp)
                absent_answer(server, 'nonexistent-cloudlab-proof.' + runtime['private']['zone'], tcp=tcp)
        retry(lambda: success(https(private_host, address=runtime['private']['tailnet_gateway'])), 'tailnet private HTTPS')
        api = https(api_url.hostname, address=api_address, path='/api/v1/namespaces')
        if api['status'] != 200 or json.loads(api['body']).get('kind') != 'NamespaceList':
            raise RuntimeError('Approved tailnet user lacks expected Kubernetes RBAC')
        output.update(private_dns_udp_tcp=True, private_https=True, api_rbac_administrator=True)
        output.update(remote('dns-proof', private=private))
        if socket.gethostbyname(private_host) != runtime['private']['tailnet_gateway']:
            raise RuntimeError('Authorized client default DNS did not select the tailnet private gateway')
        output['tailnet_default_dns'] = True
        output.update(denied_tailnet(api_url.hostname, api_address, runtime['private']['tailnet_gateway'], nameservers))
        print(json.dumps(output, sort_keys=True), flush=True)
        if failures:
            probes = {
                'cloudlab-connectors/app=cloudflared': lambda: success(https(categories['machine'][0], headers=headers)),
                'cloudlab-gateway-public/gateway.networking.k8s.io/gateway-name=cloudlab': lambda: success(https(public_host)),
                'cloudlab-gateway-private/gateway.networking.k8s.io/gateway-name=cloudlab': lambda: success(https(private_host, address=runtime['private']['tailnet_gateway'])),
                'tailscale/cloudlab.io/proxy=cloudlab-ingress': lambda: success(https(private_host, address=runtime['private']['tailnet_gateway'])),
                'tailscale/cloudlab.io/proxy=cloudlab-api': lambda: https(api_url.hostname, address=api_address, path='/api/v1/namespaces')['status'] == 200,
            }
            output['disruptions'] = {}
            for component, probe in probes.items():
                output['disruptions'][component] = disruption(component, probe)
                print(json.dumps({'component': component, **output['disruptions'][component]}), flush=True)
        output.update(human_evidence())
        if remote('identities') != identities:
            raise RuntimeError('Disposable failure changed a persisted proxy identity')
        output['proxy_identities_preserved'] = True
        output['acceptance_passed'] = failures
        return output
    finally:
        if not keep:
            remote('cleanup')


def run(*, failures=True, keep=False):
    import fcntl
    directory = Path('/state/connectivity')
    directory.mkdir(mode=0o700, exist_ok=True)
    with (directory / 'verification.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = _run(failures=failures, keep=keep)
        if failures and not keep:
            identities = remote('identities')
            with transaction() as receipts:
                external = receipts.load('external')
                receipts.save('acceptance', {'verified_at': int(time.time()), 'identities': identities,
                    'external_binding': external['binding'], 'evidence': result})
        temporary = directory / 'last-traffic.tmp'
        descriptor = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(result, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(directory / 'last-traffic.json')
        return result


if __name__ == '__main__':
    try:
        print(json.dumps(run(), sort_keys=True))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError) else 'Access traffic proof failed: ' + type(error).__name__) from None

"""Write trusted evidence only after the isolated Compose checks complete."""
import hashlib
import hmac
import json
from pathlib import Path
import re
import urllib.request

from .control import CANDIDATE, CONTROL, allowed, bot_owners, helper_hash, load, save
from .gate import Gate, canonical
from .inventory import fingerprint, selected
from .workspace import changes, files, tree


class PublicGitHub:
    def request(self, method, path, body=None):
        if method != 'GET' or not path.startswith('repos/') or '?' in path:
            raise ValueError('Credential-free verification permits only exact public GitHub reads')
        request = urllib.request.Request('https://api.github.com/' + path,
                                         headers={'Accept': 'application/vnd.github+json'})
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)


def write():
    plan = load('operation.json')
    owners = bot_owners(plan['owners'])
    checks = json.loads(Path('/results/checks.json').read_bytes())
    check_plan = load('check-plan.json')
    toolchain_record = load('toolchain.json')
    if (toolchain_record['operation'] != plan['operation'] or
            toolchain_record['candidateTree'] != tree(CANDIDATE) or
            toolchain_record['role'] != 'candidate-runner'):
        raise ValueError('Verification toolchain record is missing or stale')
    expected = {path: 'PASS' for path in plan['checks']}
    if (checks != {'operation': plan['operation'], 'candidateTree': tree(CANDIDATE),
                   'checks': expected, 'plan': hashlib.sha256(json.dumps(check_plan, sort_keys=True).encode()).hexdigest()}):
        raise ValueError('Maintenance check evidence differs from the current candidate')
    baseline = load('baseline.json')
    patch = changes(CANDIDATE, baseline, allowed(owners, set(baseline) | set(files(CANDIDATE))))
    from .keycloak import LOCK, fingerprint as identity_fingerprint, required as identity_required
    if identity_required(CANDIDATE, check_plan):
        proof = json.loads(Path('/proof-results/keycloak.json').read_bytes())
        identity = json.loads((CANDIDATE / LOCK).read_bytes())
        if (identity.get('operator_install_verified') is not True or
                proof != {'candidateTree': tree(CANDIDATE), 'inputs': identity_fingerprint(identity), 'passed': True}):
            raise ValueError('Changed identity artifacts require the existing isolated Operator/server qualification')
    ci_scans = None
    renovate_proof = None
    if 'image:maintenance' in owners:
        renovate_proof = json.loads(Path('/proof-results/renovate.json').read_bytes())
        pin = json.loads((CANDIDATE / 'platform/delivery/dependencies/image.lock.json').read_bytes())
        if renovate_proof != {'operation': plan['operation'], 'candidateTree': tree(CANDIDATE), 'image': pin['image'], 'passed': True}:
            raise ValueError('Renovate engine changes require actual pinned native validation and extraction')
    browser_proof = None
    if 'identity-browser' in owners:
        record = load('images/identity-browser.json')
        browser_proof = json.loads(Path('/proof-results/browser.json').read_bytes())
        browser_package = json.loads((CANDIDATE / 'ansible/playbooks/keycloak/tests/browser/package.json').read_bytes())
        if (record['operation'] != plan['operation'] or record['candidateTree'] != tree(CANDIDATE) or
                record['role'] != 'identity-browser' or browser_proof != {
                    **record, 'version': browser_package['dependencies']['playwright'], 'passed': True}):
            raise ValueError('Mandatory native browser build proof is missing or stale')
    if any(owner['updater'] in {'ci-tools', 'ci-runner'} for owner in owners.values()):
        proof = json.loads(Path('/proof-results/ci-images.json').read_bytes())
        expected_inputs = {'Dockerfile': 'platform/delivery/ci/Dockerfile',
                           'tools.lock.json': 'platform/delivery/ci/tools/source.lock.json',
                           'runner.lock.json': 'platform/delivery/ci/runner/source.lock.json'}
        expected_proof = {'candidateTree': tree(CANDIDATE), 'stages': ['controller', 'builder', 'runner'],
                          'inputs': {name: hashlib.sha256((CANDIDATE / path).read_bytes()).hexdigest()
                                     for name, path in expected_inputs.items()}}
        if proof != expected_proof:
            raise ValueError('Mandatory native CI image build proof is missing or stale')
        scans = json.loads(Path('/proof-results/ci-scans.json').read_bytes())
        policy = json.loads((CANDIDATE / 'platform/delivery/ci/scan.lock.json').read_bytes())
        if (scans.get('candidateTree') != tree(CANDIDATE) or scans.get('scanPolicy') != policy or
                scans.get('passed') is not True or scans.get('requiredChecks') != 'existing bootstrap.prepare' or
                set(scans.get('images', {})) != {'controller', 'runner', 'builder'} or
                set(scans.get('imageIds', {})) != {'controller', 'runner', 'builder'}):
            raise ValueError('Mandatory original-archive CI vulnerability scan is missing or stale')
        ci_scans = scans
    gate = Gate(PublicGitHub(), plan['scope'], CONTROL)
    row = gate.current(plan['number'])
    if not row.get('draft') or row['head']['sha'] != plan['head'] or row['base']['sha'] != plan['base']:
        raise ValueError('Published maintenance head or base changed during verification')
    # Every source image is pinned; helper/pinset hashes also bind locally built tools.
    toolchain = sorted(set(re.findall(r'[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}',
                                     (CANDIDATE / 'ansible/runner/Dockerfile').read_text())))
    toolchain.append(json.loads((Path(__file__).resolve().parents[4] /
                                 'platform/delivery/dependencies/image.lock.json').read_text())['image'])
    toolchain.append('cloudlab-maintenance-candidate@' + toolchain_record['imageId'])
    if ci_scans:
        toolchain.extend('cloudlab-maintenance-ci-' + role + '@' + image_id
                         for role, image_id in sorted(ci_scans['imageIds'].items()))
        toolchain.append(ci_scans['scanPolicy']['database'])
    if browser_proof:
        toolchain.append('cloudlab-maintenance-browser@' + browser_proof['imageId'])
    if renovate_proof:
        toolchain.append(renovate_proof['image'])
    evidence = {'head': plan['head'], 'base': plan['base'], 'candidateTree': tree(CANDIDATE),
                'pinset': fingerprint(CANDIDATE, owners), 'helpers': helper_hash(),
                'toolchain': toolchain, 'checks': expected}
    document = {'operation': plan['operation'], 'number': plan['number'], 'scope': plan['scope'], **evidence}
    save('validated.json', {'body': document,
         'mac': hmac.new(gate.key, canonical(document), hashlib.sha256).hexdigest()})
    if not patch:
        gate.stamp(plan['number'], evidence)
    return {'verified': True, 'publishedHeadVerified': not bool(patch), 'checks': len(expected)}


if __name__ == '__main__':
    try:
        print(json.dumps(write()))
    except Exception:
        raise SystemExit('Maintenance receipt refused; candidate or published source differs') from None

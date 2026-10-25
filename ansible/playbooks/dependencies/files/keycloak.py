"""Update official identity artifacts and require the existing isolated qualification."""
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from . import images
from .inputs import baseline
from .security import digest, download, owned_path
from .tools import write_json
from .workspace import tree

LOCK = 'platform/identity/keycloak/artifact.lock.json'
CRITICAL = ('operator_version', 'server_version', 'config_cli_version', 'config_cli_build_server', 'sources')
PHASE = 'input'


def fingerprint(lock):
    document = {name: lock[name] for name in CRITICAL}
    document['images'] = {name: lock['images'][name] for name in ('operator', 'server', 'config_cli')}
    return digest(json.dumps(document, sort_keys=True).encode())


def required(root, plan):
    if LOCK not in plan['baseFiles']:
        return False
    before = json.loads(base64.b64decode(plan['baseFiles'][LOCK], validate=True))
    return fingerprint(before) != fingerprint(json.loads(owned_path(root, LOCK).read_bytes()))


def update(root, request, *, fetch=download):
    if (set(request) != {'operator', 'server', 'configCli', 'configCliServer'} or
            any(not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', value) for value in request.values())):
        raise ValueError('Keycloak requires all four explicit compatible component versions')
    target = owned_path(root, LOCK)
    lock = json.loads(target.read_bytes())
    original = json.loads(baseline(root, LOCK))
    fields = {'operator': 'operator_version', 'server': 'server_version',
              'configCli': 'config_cli_version', 'configCliServer': 'config_cli_build_server'}
    for name, field in fields.items():
        if request[name].split('.')[:2] != original[field].split('.')[:2]:
            raise ValueError('Keycloak minor changes require separate compatibility review')
    sources, raw_sources = {}, {}
    for filename in original['sources']:
        if filename not in {'kubernetes.yml', 'keycloaks.k8s.keycloak.org-v1.yml', 'keycloakrealmimports.k8s.keycloak.org-v1.yml'}:
            raise ValueError('Unsupported Keycloak raw artifact')
        prefix = 'https://raw.githubusercontent.com/keycloak/keycloak-k8s-resources/'
        url = prefix + request['operator'] + '/kubernetes/' + filename
        raw = fetch(url, prefix=prefix)
        import yaml
        if not any(yaml.safe_load_all(raw)):
            raise ValueError('Official Keycloak artifact is empty')
        sources[filename], raw_sources[filename] = {'url': url, 'sha256': digest(raw)}, raw
    desired = {'operator': 'quay.io/keycloak/keycloak-operator:' + request['operator'],
               'server': 'quay.io/keycloak/keycloak:' + request['server'],
               'config_cli': 'quay.io/adorsys/keycloak-config-cli:' + request['configCli'] + '-' + request['configCliServer']}
    for key, reference in desired.items():
        lock['images'][key] = images.image_digest(reference)
    for name, field in fields.items():
        lock[field] = request[name]
    lock['sources'], lock['operator_install_verified'] = sources, False
    for filename, raw in raw_sources.items():
        owned_path(root, 'platform/identity/keycloak/upstream/' + filename).write_bytes(raw)
    write_json(target, lock)
    return {'owner': 'chart:identity/keycloak', 'status': 'pending-qualification',
            'qualification': 'existing isolated Operator/server proof',
            'next': 'docker compose --env-file <work>/control/toolchain.env -f ansible/playbooks/dependencies/compose.yaml run --rm qualify-keycloak'}


def prove(root=Path('/workspace')):
    global PHASE
    from .check import validated
    PHASE = 'source'
    plan = json.loads(Path('/plan.json').read_bytes())
    before = validated(root, plan)
    PHASE = 'provenance'
    provenance(root)
    PHASE = 'isolated-proof'
    result = subprocess.run([sys.executable, str(root / 'ansible/playbooks/keycloak/tests/operator_proof.py')],
                            cwd=root, capture_output=True, text=True, timeout=2400,
                            env={'PATH': os.environ['PATH'], 'HOME': '/tmp/home',
                                 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': str(root / 'ansible')})
    lines = result.stdout.splitlines()
    if result.returncode or not lines or len(result.stdout) > 1024 * 1024:
        report = Path('/reports/keycloak')
        report.mkdir(mode=0o700, parents=True, exist_ok=True)
        log = report / (plan['operation'] + '.log')
        log.write_text((result.stdout + result.stderr)[-1024 * 1024:])
        log.chmod(0o600)
        raise ValueError('Existing isolated Operator/server qualification failed')
    PHASE = 'evidence'
    evidence = json.loads(lines[-1])
    lock = json.loads((root / LOCK).read_bytes())
    flags = ('operator_ready', 'server_ready', 'repeat_preserved_statefulset', 'cr_change_reconciled',
             'operator_stop_resume', 'stable_security_admission')
    if (evidence.get('operator') != lock['operator_version'] or evidence.get('server') != lock['server_version'] or
            evidence.get('preview_client_crds') is not False or any(evidence.get(name) is not True for name in flags) or
            tree(root) != before):
        raise ValueError('Isolated identity evidence differs from the candidate')
    Path('/results/keycloak.json').write_text(json.dumps({'operation': plan['operation'], 'candidateTree': before,
                                                        'inputs': fingerprint(lock), 'passed': True}) + '\n')
    return {'qualified': True, 'environment': 'isolated Compose Kubernetes'}


def provenance(root, *, fetch=download, plan=None):
    lock = json.loads((root / LOCK).read_bytes())
    def approved(relative):
        return base64.b64decode(plan['baseFiles'][relative], validate=True) if plan is not None else baseline(root, relative)
    original = json.loads(approved(LOCK))
    for filename, pin in lock['sources'].items():
        prefix = 'https://raw.githubusercontent.com/keycloak/keycloak-k8s-resources/'
        expected = prefix + lock['operator_version'] + '/kubernetes/' + filename
        if pin['url'] != expected or filename not in {
                'kubernetes.yml', 'keycloaks.k8s.keycloak.org-v1.yml', 'keycloakrealmimports.k8s.keycloak.org-v1.yml'}:
            raise ValueError('Identity artifact differs from its official component release')
        relative = 'platform/identity/keycloak/upstream/' + filename
        current = owned_path(root, relative).read_bytes()
        if digest(current) != pin['sha256']:
            raise ValueError('Identity raw artifact checksum differs')
        if pin == original['sources'][filename] and current == approved(relative):
            continue
        raw = fetch(expected, prefix=prefix, sha256=pin['sha256'])
        if raw != current:
            raise ValueError('Identity raw artifact differs from the checksum-verified official source')
    for name in ('operator', 'server', 'config_cli'):
        reference = lock['images'][name]
        images.reference(reference)
        if reference != original['images'][name] and images.image_digest(reference.split('@')[0]) != reference:
            raise ValueError('Identity image differs from its official release digest')


def accept(root=Path('/candidate')):
    global PHASE
    PHASE = 'record'
    plan = json.loads(Path('/control/check-plan.json').read_bytes())
    lock = json.loads((root / LOCK).read_bytes())
    result = json.loads(Path('/results/keycloak.json').read_bytes())
    if result != {'operation': plan['operation'], 'candidateTree': tree(root), 'inputs': fingerprint(lock), 'passed': True}:
        raise ValueError('Identity qualification result is missing or stale')
    lock['operator_install_verified'] = True
    write_json(root / LOCK, lock)
    Path('/proof-results/keycloak.json').write_text(json.dumps({'candidateTree': tree(root), 'inputs': fingerprint(lock),
                                                              'passed': True}) + '\n')
    return {'qualified': True, 'next': 'record current candidate toolchain, then verify'}


if __name__ == '__main__':
    try:
        function = {'prove': prove, 'accept': accept}[sys.argv[1]]
        print(json.dumps(function()))
    except Exception as error:
        print(json.dumps({'qualified': False, 'stage': PHASE, 'errorClass': type(error).__name__}))
        raise SystemExit('Identity dependency qualification failed; candidate stays draft') from None

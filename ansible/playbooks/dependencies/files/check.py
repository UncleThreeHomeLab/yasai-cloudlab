"""Run existing owner checks inside the credential-free candidate container."""
import json
import base64
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import re

from .security import digest, owned_path
from .workspace import tree
from .workspace import files
from .validate import file_change
from .toolchain import embedded


def source(root, plan):
    root = Path(root)
    if any(name in os.environ for name in ('OP_SERVICE_ACCOUNT_TOKEN', 'GITHUB_TOKEN', 'RENOVATE_TOKEN',
                                            'SSH_AUTH_SOCK', 'AWS_ACCESS_KEY_ID', 'TF_HTTP_PASSWORD')):
        raise ValueError('Candidate checks must not inherit credentials')
    before = tree(root)
    current = files(root)
    original = plan['baseTree']
    if type(plan.get('fileModes')) is not bool:
        raise ValueError('Candidate filesystem mode capability was not recorded by trusted export')
    if plan['fileModes']:
        for relative in set(current) & set(original):
            if bool(owned_path(root, relative).stat().st_mode & 0o111) != (original[relative]['mode'] == '100755'):
                raise ValueError('Maintenance changed a candidate file mode')
    changed = set(current) ^ set(original)
    for relative in set(current) & set(original):
        raw = owned_path(root, relative).read_bytes()
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        if blob != original[relative]['sha']:
            changed.add(relative)
    permitted = set(plan['allowed'])
    if plan.get('archiveOwners'):
        for owner in plan['archiveOwners'].values():
            for archive in [path for path in owner['writePaths'] if path.endswith('.tgz') and '/charts/' in path]:
                version = re.search(r'v?[0-9]+\.[0-9]+\.[0-9]+(?=[.]tgz$)', archive)
                if version:
                    pattern = re.escape(archive[:version.start()]) + r'v?[0-9]+\.[0-9]+\.[0-9]+' + re.escape(archive[version.end():])
                    permitted.update(path for path in current if re.fullmatch(pattern, path))
    if changed - permitted:
        raise ValueError('Maintenance changed initial unowned source files')
    for relative in changed:
        old = base64.b64decode(plan['baseFiles'][relative], validate=True) if relative in plan['baseFiles'] else None
        new = owned_path(root, relative).read_bytes() if relative in current else None
        file_change(relative, old, new)
    return before


def validated(root, plan):
    before = source(root, plan)
    from .compatibility import verify
    verify(root, plan)
    record = json.loads(Path('/toolchain.json').read_bytes())
    if (record != {'operation': plan['operation'], 'candidateTree': before, 'role': 'candidate-runner',
                   'imageId': os.environ.get('DEPENDENCY_VERIFIED_IMAGE_ID')} or
            not record['imageId'].startswith('sha256:')):
        raise ValueError('Verification must use the recorded immutable Docker image ID')
    embedded(root)
    from .images import provenance
    provenance(root, plan)
    from .charts import provenance as chart_provenance
    from .artifacts import provenance as raw_provenance
    from .tools import provenance as tool_provenance
    chart_provenance(root, plan)
    raw_provenance(root, plan)
    tool_provenance(root, plan)
    from .keycloak import LOCK, provenance as identity_provenance
    if LOCK in plan['baseFiles']:
        identity_provenance(Path(root), plan=plan)
    return before


def run(root, plan, output):
    root = Path(root)
    before = validated(root, plan)
    checks = {}
    for relative in plan['checks']:
        if relative.startswith('native:'):
            from .native import ROOTS, lock_and_check
            from .providers import ROOTS as CUSTOM_ROOTS
            name = relative.removeprefix('native:')
            if name == 'cosign':
                from .tools import check_cosign
                check_cosign(root)
                checks[relative] = 'PASS'
                continue
            if name == 'sigstore-roots':
                from .trust import verify
                verify(root)
                checks[relative] = 'PASS'
                continue
            if name == 'oauth2-proxy':
                from .tools import check_oauth2
                check_oauth2(root)
                checks[relative] = 'PASS'
                continue
            if name == 'cmctl':
                from .tools import check_cmctl
                check_cmctl(root)
                checks[relative] = 'PASS'
                continue
            roots = (ROOTS[name],) if name in ROOTS else CUSTOM_ROOTS.get(name)
            if not roots:
                raise ValueError('Unsupported native verification owner')
            for directory in roots:
                lock_and_check(root / directory, update=False)
            checks[relative] = 'PASS'
            continue
        module_checks = {'module:playbooks.keycloak.files.chart': 'playbooks.keycloak.files.chart',
                         'module:playbooks.data.files.chart': 'playbooks.data.files.chart',
                         'module:playbooks.harbor.files.chart': 'playbooks.harbor.files.chart',
                         'module:playbooks.rollouts.files.check': 'playbooks.rollouts.files.check',
                         'module:playbooks.access.files.dns_check': 'playbooks.access.files.dns_check',
                         'module:playbooks.previews.files.check': 'playbooks.previews.files.check',
                         'module:playbooks.previews.files.package': 'playbooks.previews.files.package',
                         'module:playbooks.services.files.package': 'playbooks.services.files.package'}
        path = owned_path(root, relative) if relative not in module_checks else root / 'ansible/playbooks/dependencies/tests/check.py'
        # The plan is written by trusted export, not read from candidate code.
        command = ([sys.executable, '-m', module_checks[relative]] if relative in module_checks else
                   [sys.executable, '-m', 'unittest', 'discover', '-s', str(path.parent), '-p', path.name])
        environment = {'PATH': os.environ['PATH'], 'HOME': '/tmp/home', 'PYTHONDONTWRITEBYTECODE': '1',
                       'ANSIBLE_REMOTE_TMP': '/tmp/ansible-remote',
                       'PYTHONPATH': os.pathsep.join(map(str, (path.parent.parent, path.parent.parent / 'files',
                                                              root / 'ansible', root, root / 'verification/integration')))}
        result = subprocess.run(command, cwd=root, env=environment, capture_output=True, timeout=600)
        if result.returncode or (relative not in module_checks and not re.search(
                rb'Ran [1-9][0-9]* tests? in ', result.stderr + result.stdout)):
            raise RuntimeError('Required maintenance check failed: ' + relative)
        checks[relative] = 'PASS'
    if tree(root) != before:
        raise ValueError('Candidate checks changed maintained source files')
    document = {'operation': plan['operation'], 'candidateTree': before, 'checks': checks,
                'plan': digest(json.dumps(plan, sort_keys=True).encode())}
    Path(output).write_text(json.dumps(document, sort_keys=True) + '\n')
    return {'checks': len(checks), 'passed': True}


if __name__ == '__main__':
    try:
        print(json.dumps(run('/workspace', json.loads(Path('/plan.json').read_text()), '/results/checks.json')))
    except (ValueError, RuntimeError, subprocess.SubprocessError):
        raise SystemExit('Maintenance checks failed; private diagnostics withheld') from None

"""Credential-free dependency maintenance entry point."""
import json
import os
from pathlib import Path
import sys
import subprocess

from . import actions, artifacts, browser, charts, ci_runner, ci_tools, images, keycloak, native, profiles, providers, requirements, tools, trust
from .inventory import selected
from .workspace import changes


def maintain(kind, name, request, root=Path('/candidate')):
    if any(key in os.environ for key in ('OP_SERVICE_ACCOUNT_TOKEN', 'GITHUB_TOKEN', 'RENOVATE_TOKEN', 'SSH_AUTH_SOCK')):
        raise ValueError('Maintenance must run without credentials')
    if not Path('/plan.json').is_file():
        raise ValueError('Maintenance requires an exported owned candidate plan')
    from .check import source
    source(root, json.loads(Path('/plan.json').read_bytes()))
    if kind == 'package' and name in {'notes', 'previews'} and request == {}:
        module = {'notes': 'playbooks.services.files.package', 'previews': 'playbooks.previews.files.package'}[name]
        result = subprocess.run([sys.executable, '-m', module, 'build'], cwd=root, capture_output=True, timeout=120,
                                env={'PATH': os.environ['PATH'], 'HOME': '/tmp/home', 'PYTHONDONTWRITEBYTECODE': '1',
                                     'PYTHONPATH': str(Path(root) / 'ansible') + os.pathsep + str(root)})
        if result.returncode:
            raise ValueError('Existing dependency owner packaging failed')
        return {'owner': 'notes-package' if name == 'notes' else 'preview-package', 'status': 'pending-verification'}
    if kind in ('cloudflare-provider', 'harbor-provider') and name == 'source':
        return providers.prepare(root, kind.removesuffix('-provider'), request)
    if kind == 'ci-runner' and name == 'source':
        return ci_runner.update(root, request)
    if kind == 'finalize' and name == 'ci-runner' and request == {}:
        return ci_runner.finalize(root)
    if kind == 'finalize' and name == 'helm' and request == {}:
        return tools.finalize_helm(root)
    if kind == 'finalize' and name == 'cosign' and request == {}:
        return tools.finalize_cosign(root)
    if kind == 'image':
        return images.update(root, name, request)
    if kind == 'profile' and name == 'buildkit':
        return profiles.update(root, request)
    if kind == 'requirements' and name == 'python':
        return requirements.update(root, request)
    if kind == 'chart' and name == 'identity/keycloak':
        return keycloak.update(root, request)
    if kind == 'browser' and name == 'playwright':
        return browser.update(root, request)
    if kind == 'trust' and name == 'sigstore':
        return trust.update(root, request)
    if set(request) != {'version'}:
        raise ValueError('Maintenance requires one explicit version or immutable revision')
    if kind == 'tool':
        owner = name if name in {'tailscale', 'k3s'} else 'tool:' + name
        selected([owner])
        return tools.update(root, name, request['version'])
    if kind == 'actions' and name == 'checkout':
        selected(['actions'])
        return actions.update(root, request['version'])
    if kind == 'registry':
        return native.registry(root, name, request['version'])
    if kind == 'ci-tools':
        return ci_tools.update(root, name, request['version'])
    if kind == 'chart':
        if name in artifacts.OWNERS:
            return artifacts.update(root, name, request['version'])
        return charts.update(root, name, request['version'])
    raise ValueError('Unsupported maintenance owner')


if __name__ == '__main__':
    try:
        if len(sys.argv) not in (2, 3):
            raise ValueError('Use maintain OWNER [NAME]')
        raw = sys.stdin.read(16385)
        if len(raw) > 16384:
            raise ValueError('Maintenance request exceeds its size limit')
        name = sys.argv[2] if len(sys.argv) == 3 else ('checkout' if sys.argv[1] == 'actions' else 'source')
        request = {} if not raw.strip() and sys.argv[1] in {'finalize', 'package'} else json.loads(raw)
        result = maintain(sys.argv[1], name, request)
        pending = result.get('pendingBuild') or result.get('requiresBuild')
        if pending:
            stages = [pending] if isinstance(pending, str) else pending
            fixed = {'candidate-runner', 'candidate-ci-controller', 'candidate-ci-builder', 'candidate-ci-runner',
                     'review-cloudflare-provider', 'review-harbor-provider', 'refresh-ci-runner', 'ci-build-proof',
                     'identity-browser'}
            if set(stages) - fixed:
                raise ValueError('Unsupported maintenance build stage')
            result['status'] = 'pending-build'
            if 'next' not in result:
                result['next'] = 'docker compose -f ansible/playbooks/dependencies/compose.yaml build ' + ' '.join(stages)
        print(json.dumps(result))
    except Exception:
        raise SystemExit('Dependency maintenance failed; candidate remains draft') from None

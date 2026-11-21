"""Read and validate the private Git source registry; never log its values."""
import base64
import json
import copy
from pathlib import Path
import re

CONSUMERS = ('observability', 'permissions', 'services')


def decode_contents(document):
    encoded = document.get('content')
    if not isinstance(encoded, str) or len(encoded) > 2 * 1024 * 1024:
        raise RuntimeError('Private source exceeds its bounded content contract')
    # GitHub's Contents API wraps base64 with line endings; other garbage fails.
    raw = base64.b64decode(encoded.replace('\r', '').replace('\n', ''), validate=True)
    if len(raw) > 1024 * 1024:
        raise RuntimeError('Private source exceeds its bounded content contract')
    return raw


def argo_values(api, values, revision, identity_issuer, origin, additional_origins):
    """Accept the reviewed Argo OIDC overlay only when it matches the contract.

    Port of the retired inventory cross-check: the pre-R2 identity runtime
    was trimmed in #511, so the native inventory half of the old comparison
    no longer exists. The overlay file stays the reviewed source and the
    construction rules it used to satisfy are enforced here instead: an
    immutable private revision, a bounded 1MB file read, the exact pre-R2
    native PKCE contract built from the anchored platform issuer and the
    distinct public/private origins, and exact equality of the decoded
    overlay with that contract. The Keycloak-side client itself is owned by
    the identity writer; this function guards only what the mesh accepts
    as its OIDC overlay.
    """
    import importlib.util
    from urllib.parse import urlsplit
    import yaml
    from playbooks.argocd.files.github_setup import inspect, repository
    if not re.fullmatch('[a-f0-9]{40}', revision or ''):
        raise ValueError('Private Argo values require an immutable commit')
    repo = repository(values.get('PRIVATE_CONFIG_REPOSITORY'))
    if inspect(api, 'private-config', repo, True) is None:
        raise RuntimeError('Designated private identity repository is unavailable')
    runtime = Path(__file__).resolve().parents[4].joinpath(
        'platform/identity/keycloak/runtime/configuration.py')
    spec = importlib.util.spec_from_file_location('identity_configuration', runtime)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    parsed = urlsplit(module.exact_url(identity_issuer))
    if parsed.path != '/realms/platform':
        raise ValueError('Administrative applications require the platform issuer')
    if (not isinstance(origin, str) or not isinstance(additional_origins, list)
            or len(additional_origins) != 1
            or any(not isinstance(item, str) for item in additional_origins)):
        raise ValueError('Argo requires distinct bounded public/private origins')
    origins = [origin] + additional_origins
    if len(set(origins)) != len(origins):
        raise ValueError('Argo requires distinct bounded public/private origins')
    for address in origins:
        if urlsplit(module.exact_url(address + '/auth/callback')).path != '/auth/callback':
            raise ValueError('Argo origin must contain no path')
    obj = api.request(
        'GET', 'repos/' + repo + '/contents/identity/argo-values.yaml?ref=' + revision)
    if (obj.get('type') != 'file' or obj.get('encoding') != 'base64'
            or obj.get('size', 1048577) > 1048576):
        raise RuntimeError('Private Argo source must be a bounded regular file')
    raw = decode_contents(obj)
    if len(raw) != obj['size']:
        raise RuntimeError('Private Argo source differs from its bounded file contract')
    if len(raw) > 1048576:
        raise RuntimeError('Private Argo source exceeds its limit')
    config = {'name': 'Keycloak', 'issuer': identity_issuer, 'clientID': 'argocd',
              'enablePKCEAuthentication': True, 'refreshTokenThreshold': '2m',
              'requestedScopes': ['openid', 'profile', 'email']}
    expected = {'argo-cd': {'configs': {
        'cm': {'url': origin, 'additionalUrls': yaml.safe_dump(origins[1:], sort_keys=True),
               'users.session.duration': '10m',
               'oidc.config': yaml.safe_dump(config, sort_keys=True)},
        'rbac': {'policy.default': 'role:no-access', 'scopes': '[groups]',
                 'policy.csv': '\n'.join([
                     'g, /platform-admin, role:admin',
                     'g, /developer, role:developer',
                     'g, /viewer, role:viewer',
                     'p, role:developer, applications, get, cloudlab-public/*, allow',
                     'p, role:developer, applications, sync, cloudlab-public/*, allow',
                     'p, role:developer, logs, get, cloudlab-public/*, allow',
                     'p, role:viewer, applications, get, cloudlab-public/*, allow',
                     'p, role:viewer, logs, get, cloudlab-public/*, allow'])}}}}
    overlay = yaml.load(raw, Loader=strict_loader('Argo overlay'))
    if overlay != expected:
        raise RuntimeError('Private Argo overlay differs from its reviewed OIDC contract')
    return {'helm': expected}


def strict_loader(name):
    import yaml
    class StrictLoader(yaml.SafeLoader):
        def compose_node(self, parent, index):
            if self.check_event(yaml.AliasEvent):
                raise ValueError(name)
            return super().compose_node(parent, index)
        def construct_mapping(self, node, deep=False):
            pairs = self.construct_pairs(node, deep=deep)
            if any(not isinstance(key, str) for key, _ in pairs) or len(dict(pairs)) != len(pairs):
                raise ValueError(name)
            return dict(pairs)
    return StrictLoader


def render_objects(files, documents, *, release='cloudlab-public-root', namespace='argocd'):
    """Render chart bytes with pinned Helm; used for declaration capture only."""
    import json
    import subprocess
    import tempfile
    import yaml
    from pathlib import PurePosixPath
    if (not isinstance(release, str) or not re.fullmatch('[a-z0-9](?:[a-z0-9-]{0,51}[a-z0-9])?', release)
            or not isinstance(namespace, str) or not re.fullmatch('[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', namespace)):
        raise ValueError('Chart rendering requires bounded DNS release and namespace names')
    with tempfile.TemporaryDirectory(prefix='cloudlab-source-owner-') as directory:
        root = Path(directory) / 'chart'
        root.mkdir()
        for name, raw in files.items():
            path = root.joinpath(*PurePosixPath(name).parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        command = ['helm', 'template', release, str(root), '-n', namespace, '--kube-version', '1.36.5']
        for index, document in enumerate(documents):
            path = Path(directory) / ('input-' + str(index) + '.json')
            path.write_text(json.dumps(document))
            path.chmod(0o600)
            command += ['-f', str(path)]
        with tempfile.TemporaryFile() as output:
            result = subprocess.run(command, stdout=output, stderr=subprocess.DEVNULL, timeout=60)
            if result.returncode or output.tell() > 2 * 1024 * 1024:
                raise RuntimeError('Pinned chart rejected its authenticated inputs')
            output.seek(0)
            return [obj for obj in yaml.safe_load_all(output) if obj]


def consumer_contract(public, consumer):
    """Validate supplied context only; callers must authenticate public authority."""
    from playbooks.argocd.files.github_setup import repository
    from playbooks.argocd.files.service_activation import catalog_path, consumer_paths
    if not isinstance(public, dict) or consumer not in CONSUMERS:
        raise ValueError('Consumer source configuration refused')
    repository(public.get('repository'))
    if public.get('revision') != 'main': raise ValueError('Consumer source configuration refused')
    selected = ('observability', 'services', 'identity', 'externalSecrets', 'admission') if consumer == 'observability' else (('services', 'identity', 'externalSecrets', 'admission') if consumer == 'services' else ('permissions', 'identity', 'externalSecrets', 'admission'))
    context = {key: copy.deepcopy(public.get(key, {})) for key in selected}
    if any(not isinstance(value, dict) for value in context.values()): raise ValueError('Consumer source configuration refused')
    context['identity'].pop('argo', None)  # Private identity binding is separate from public input approval.
    for key, node in context.items():
        if type(node.get('enabled', False)) is not bool: raise ValueError('Consumer source configuration refused')
    external = context['externalSecrets']
    if type(external.get('reconcile', False)) is not bool: raise ValueError('Consumer source configuration refused')
    settings = context[consumer]
    if consumer == 'observability':
        settings = settings.get('configuration', {})
        if (not isinstance(settings, dict) or type(settings.get('enabled', False)) is not bool
                or type(settings.get('paused', False)) is not bool): raise ValueError('Consumer source configuration refused')
        paths = [catalog_path(context['services'].get('catalogPath', catalog_path())), 'platform/observability.yaml']
    elif consumer == 'services':
        paths = consumer_paths(context['services'].get('catalogPath'))
    else:
        paths = ['platform/permissions.yaml']
    enabled = settings.get('enabled', False)
    if consumer == 'observability' and enabled:
        service_pin = context['services'].get('revision')
        if not isinstance(service_pin, str) or not re.fullmatch('[a-f0-9]{40}', service_pin):
            raise ValueError('Consumer source configuration refused')
    pin = settings.get('revision', '')
    if not isinstance(pin, str) or (pin and not re.fullmatch('[a-f0-9]{40}', pin)):
        raise ValueError('Consumer source configuration refused')
    if enabled and (not re.fullmatch('[a-f0-9]{40}', pin)
            or context['identity'].get('enabled') is not True or external.get('enabled') is not True or external.get('reconcile') is not True
            or (consumer == 'observability' and context['observability'].get('enabled') is not True)
            or (consumer in ('permissions', 'services') and context['admission'].get('enabled') is not True)):
        raise ValueError('Consumer source configuration refused')
    context.update(repository=public['repository'], revision=public['revision'])
    return {'consumer': consumer, 'enabled': enabled, 'paths': paths, 'context': context}


def source_spec(public, repository, revision, *, files=None, consumer='private-sources'):
    """Capture the reviewed native contract directly from its owning Root chart."""
    targets = {'private-sources': 'cloudlab-private-sources', 'permissions': 'cloudlab-permissions',
               'observability': 'cloudlab-observability-gitops', 'services': 'cloudlab-services'}
    if not isinstance(consumer, str) or consumer not in targets:
        raise ValueError('Private source declaration is unsupported')
    values = copy.deepcopy(public)
    values.setdefault('identity', {}).update(enabled=True, argo={'valuesRepository': repository, 'valuesRevision': revision})
    chart = Path(__file__).resolve().parents[4] / 'gitops/roots/public'
    if files is None:
        files = {path.relative_to(chart).as_posix(): path.read_bytes() for path in chart.rglob('*') if path.is_file()}
    sets = [obj for obj in render_objects(files, [values]) if obj['kind'] == 'ApplicationSet'
        and obj['metadata']['name'] == targets[consumer]]
    if len(sets) != 1: raise ValueError('Private source declaration is missing')
    return sets[0]['spec']


PEM_TEMPLATE = r'''{{- $key := .PRIVATE_KEY | trim -}}
{{- $header := regexFind "^-----BEGIN (RSA )?PRIVATE KEY-----" $key -}}
{{- $footer := replace "BEGIN" "END" $header -}}
{{- $body := $key | trimPrefix $header | trimSuffix $footer -}}
{{- printf "%s\n%s\n%s\n" $header (regexReplaceAll "[[:space:]]+" $body "") $footer -}}'''


def registry_enabled(public):
    settings = public.get('privateSources', {})
    if not isinstance(settings, dict):
        raise ValueError('Private source settings must be a mapping')
    enabled = settings.get('enabled', False)
    if type(enabled) is not bool:
        raise ValueError('privateSources.enabled must be a YAML boolean')
    if enabled and (public.get('admission', {}).get('enabled') is not True or
                    public.get('externalSecrets', {}).get('enabled') is not True or
                    public.get('externalSecrets', {}).get('reconcile') is not True):
        raise ValueError('Private source catalog requires admission and External Secrets')
    return enabled


def validate_registry(value):
    """Validate the complete private input with the same native chart Argo consumes."""
    import subprocess
    if (not isinstance(value, dict) or set(value) != {'sources'} or not isinstance(value['sources'], list)
            or len(value['sources']) > 20 or any(not isinstance(row, dict) or
                set(row) != {'name', 'repository', 'revision', 'path'} or
                any(not isinstance(item, str) for item in row.values()) for row in value['sources'])):
        raise ValueError('Private registry requires its explicit complete sources list')
    chart = Path(__file__).resolve().parents[4] / 'platform/delivery/private-sources'
    result = subprocess.run(['helm', 'template', 'private-sources', str(chart), '-n', 'argocd', '-f', '-'],
                            input=json.dumps(value), capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise ValueError('Private registry violates its bounded native chart contract')
    return value


def registry(client, values, public, revision):
    """Read the complete registry only at its authenticated immutable snapshot revision."""
    if not registry_enabled(public):
        return None
    if json.loads(values.get('PRIVATE_GITOPS_SOURCES') or '[]') != [] or values.get('PRIVATE_GITOPS_REMOVE'):
        raise ValueError('Legacy private source inputs are retired; migrate their owned registrations explicitly')
    if not isinstance(revision, str) or not re.fullmatch('[a-f0-9]{40}', revision):
        raise ValueError('Private registry requires its immutable private source revision')
    import yaml
    from playbooks.argocd.files.github_setup import repository
    document = client.request('GET', 'repos/' + repository(values['PRIVATE_CONFIG_REPOSITORY']) +
                              '/contents/platform/sources.yaml?ref=' + revision)
    if (not isinstance(document, dict) or document.get('type') != 'file' or document.get('encoding') != 'base64'
            or type(document.get('size')) is not int or not 0 <= document['size'] <= 1048576):
        raise ValueError('Private registry must be a bounded regular file')
    return validate_registry(yaml.load(decode_contents(document), Loader=strict_loader('Private registry input is invalid')))


def permissions_input(client, repository, revision):
    """Read normalized permissions from the same authenticated private snapshot."""
    import yaml
    from playbooks.argocd.files.github_setup import repository as repository_name
    if not isinstance(revision, str) or not re.fullmatch('[a-f0-9]{40}', revision):
        raise ValueError('Permissions require an immutable private snapshot')
    document = client.request('GET', 'repos/' + repository_name(repository) +
        '/contents/platform/permissions.yaml?ref=' + revision)
    if (not isinstance(document, dict) or document.get('type') != 'file'
            or document.get('encoding') != 'base64' or type(document.get('size')) is not int
            or not 0 < document['size'] <= 1048576):
        raise ValueError('Permissions require a bounded regular input file')
    raw = decode_contents(document)
    if len(raw) != document['size']:
        raise ValueError('Permissions input size differs from its source')
    value = yaml.load(raw, Loader=strict_loader('Permissions input is invalid'))
    permissions = value.get('permissions') if isinstance(value, dict) else None
    if (not isinstance(permissions, dict) or set(permissions) != {'state', 'assignments'}
            or permissions['state'] not in ('active', 'retired')
            or not isinstance(permissions['assignments'], list) or len(permissions['assignments']) > 128
            or any(not isinstance(row, dict) for row in permissions['assignments'])
            or permissions['state'] == 'retired' and permissions['assignments']):
        raise ValueError('Permissions require their complete normalized input')
    return copy.deepcopy(permissions)


def policy_specs(names):
    """Capture trusted public definitions; live policy objects are never expectations."""
    import subprocess
    import yaml
    chart = Path(__file__).resolve().parents[4] / 'platform/delivery/admission/policies'
    result = subprocess.run(['helm', 'template', 'cloudlab-workload-policy', str(chart)],
                            capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise ValueError('Private source ownership policy definitions cannot be rendered')
    return {row['metadata']['name']: row['spec'] for row in yaml.safe_load_all(result.stdout)
            if row and row['kind'] == 'ValidatingPolicy' and row['metadata']['name'] in names}


def accepted_catalog_revision(client, repository, snapshot, commitment):
    """Authenticate a receipt without exposing its private contents."""
    import hashlib
    import hmac
    import yaml
    from playbooks.argocd.files.github_setup import repository as repository_name
    try:
        if (not isinstance(snapshot, str) or not re.fullmatch('[a-f0-9]{40}', snapshot)
                or not isinstance(commitment, str) or not re.fullmatch('[a-f0-9]{64}', commitment)):
            raise ValueError()
        document = client.request('GET', 'repos/' + repository_name(repository) +
            '/contents/platform/acceptance/private-sources.yaml?ref=' + snapshot)
        if (not isinstance(document, dict) or document.get('type') != 'file'
                or document.get('encoding') != 'base64' or type(document.get('size')) is not int
                or not 0 < document['size'] <= 1048576):
            raise ValueError()
        raw = decode_contents(document)
        if len(raw) != document['size']:
            raise ValueError()
        receipt = yaml.load(raw, Loader=strict_loader('Private source acceptance is invalid'))
        if (not isinstance(receipt, dict) or set(receipt) != {'version', 'revision', 'nonce'}
                or any(type(value) is not str for value in receipt.values())
                or receipt['version'] != 'v1' or not re.fullmatch('[a-f0-9]{40}', receipt['revision'])
                or not re.fullmatch('[a-f0-9]{64}', receipt['nonce'])):
            raise ValueError()
        canonical = ('cloudlab-private-source-acceptance-v1\n' + repository +
            '\nprivate-sources\nplatform/sources.yaml\n' + receipt['revision'] + '\n' + receipt['nonce'] + '\n').encode('utf-8')
        if not hmac.compare_digest(hashlib.sha256(canonical).hexdigest(), commitment):
            raise ValueError()
        return receipt['revision']
    except Exception:
        raise ValueError('Private source acceptance is invalid') from None


def verification_approval(public):
    """Capture the protected public Root chart used for private verification."""
    import time
    import yaml
    from playbooks.argocd.files import source_snapshot
    from playbooks.argocd.files.github_app import PUBLIC_READER, public_metadata
    from playbooks.secrets.files.vault import fields
    if public.get('repository') != 'https://github.com/' + PUBLIC_READER + '.git':
        raise ValueError('Private source approval is invalid')
    deadline = time.monotonic() + 150
    with public_metadata(fields('github-argocd', ('APP_ID', 'INSTALLATION_ID', 'PRIVATE_KEY')), deadline=deadline) as fetch:
        branch = fetch('repos/' + PUBLIC_READER + '/branches/main', deadline)
        revision = branch.get('commit', {}).get('sha') if isinstance(branch, dict) else None
        if not isinstance(branch, dict) or branch.get('protected') is not True or not isinstance(revision, str) or not re.fullmatch('[a-f0-9]{40}', revision):
            raise ValueError('Private source approval is invalid')
        files = source_snapshot.chart_files({'repository': public['repository'], 'revision': revision,
            'path': 'gitops/roots/public'}, fetch=fetch, deadline=deadline)
    approved = yaml.safe_load(files['values.yaml'])
    if (not isinstance(approved, dict) or approved.get('repository') != public.get('repository')
            or approved.get('revision') != 'main' or approved.get('privateSources') != public.get('privateSources')):
        raise ValueError('Private source approval is invalid')
    return approved, files


def verification_payload(values, public):
    """Read one authenticated snapshot and render its complete immutable catalog."""
    from playbooks.argocd.files.github_app import configuration_revision
    import subprocess
    import yaml
    from urllib.parse import quote
    from playbooks.argocd.files.github_setup import repository as repository_name
    repository = values.get('PRIVATE_CONFIG_REPOSITORY')
    if not repository:
        raise ValueError('Private verification requires its designated repository')
    private_inputs = {}
    enabled = registry_enabled(public)
    approved, files = verification_approval(public) if enabled else (public, None)
    def read(client, revision):
        if consumer_contract(public, 'permissions')['enabled']:
            private_inputs['permissions'] = permissions_input(client, repository, revision)
        enabled = registry_enabled(public)
        catalog_revision = accepted_catalog_revision(client, repository, revision, approved['privateSources'].get('commitment')) if enabled else None
        value = registry(client, values, public, catalog_revision) if enabled else None
        objects = []
        symbolic_revisions = {}
        if value is not None:
            refs = {row['revision'] for row in value['sources'] if row['repository'] == repository
                    and row['revision'] != 'main' and not re.fullmatch('[a-f0-9]{40}', row['revision'])}
            for ref in sorted(refs):
                try:
                    document = client.request('GET', 'repos/' + repository_name(repository) + '/commits/' + quote(ref, safe=''))
                except Exception:
                    raise ValueError('Private source symbolic revision cannot be resolved') from None
                if (not isinstance(document, dict) or not isinstance(document.get('sha'), str)
                        or not re.fullmatch('[a-f0-9]{40}', document['sha'])):
                    raise ValueError('Private source symbolic revision resolved to an invalid commit')
                symbolic_revisions[ref] = document['sha']
            chart = Path(__file__).resolve().parents[4] / 'platform/delivery/private-sources'
            result = subprocess.run(['helm', 'template', 'private-sources', str(chart), '-n', 'argocd', '-f', '-'],
                input=json.dumps(value), capture_output=True, text=True, timeout=60)
            if result.returncode:
                raise ValueError('Private verification declarations cannot be rendered')
            objects = [obj for obj in yaml.safe_load_all(result.stdout) if obj]
        result = {'configuration_repository': repository, 'configuration_revision': revision,
                'catalog_enabled': registry_enabled(public), 'sources': value['sources'] if value else [],
                'objects': objects, 'public_repository': public['repository'],
                'symbolic_revisions': symbolic_revisions,
                'platform_revision': public.get('privateSources', {}).get('revision'),
                'catalog_revision': catalog_revision}
        if enabled:
            result.update(applicationSet=source_spec(approved, repository, revision, files=files))
        return result
    result = configuration_revision(values, read=read)
    for consumer in CONSUMERS:
        evidence = consumer_payload(values, public, repository, result['configuration_revision'], consumer)
        if evidence is not None:
            if consumer == 'permissions':
                evidence['input'] = private_inputs[consumer]
            result[consumer] = evidence
    return result


def consumer_payload(values, public, repository, head, consumer):
    """Authenticate the public consumer declaration; use one private snapshot for all paths."""
    import time
    import yaml
    from playbooks.argocd.files import source_snapshot
    from playbooks.argocd.files.github_app import PUBLIC_READER, public_metadata
    from playbooks.secrets.files.vault import fields
    contract = consumer_contract(public, consumer)
    if not contract['enabled']:
        return None
    if public['repository'] != 'https://github.com/' + PUBLIC_READER + '.git':
        raise ValueError('Consumer verification requires the designated public repository')
    if not isinstance(head, str) or not re.fullmatch('[a-f0-9]{40}', head):
        raise ValueError('Consumer verification requires an immutable private snapshot')
    deadline = time.monotonic() + 150
    credentials = fields('github-argocd', ('APP_ID', 'INSTALLATION_ID', 'PRIVATE_KEY'))
    with public_metadata(credentials, deadline=deadline) as fetch:
        branch = fetch('repos/' + PUBLIC_READER + '/branches/main', deadline)
        if (not isinstance(branch, dict) or branch.get('protected') is not True
                or not isinstance(branch.get('commit', {}).get('sha'), str)
                or not re.fullmatch('[a-f0-9]{40}', branch['commit']['sha'])):
            raise ValueError('Public approval head is invalid')
        public_revision = branch['commit']['sha']
        files = source_snapshot.chart_files({'repository': public['repository'], 'revision': public_revision,
            'path': 'gitops/roots/public'}, fetch=fetch, deadline=deadline)
    approved = yaml.safe_load(files['values.yaml'])
    if consumer_contract(approved, consumer) != contract:
        raise ValueError('Consumer verification differs from authenticated public intent')
    return {'publicRevision': public_revision, 'sourceRevision': head,
        'contract': contract, 'applicationSet': source_spec(
            approved, repository, head, files=files, consumer=consumer)}


if __name__ == '__main__':
    import sys
    try:
        import os
        from dotenv import dotenv_values
        import yaml
        root = Path(__file__).resolve().parents[4]
        values = dotenv_values(root / '.env', interpolate=False)
        os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
        print(json.dumps(verification_payload(values, yaml.safe_load(
            (root / 'gitops/roots/public/values.yaml').read_text()))))
    except Exception:
        raise SystemExit('Private GitOps verification inputs unavailable; values withheld') from None

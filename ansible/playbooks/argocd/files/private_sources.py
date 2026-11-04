"""Read and validate the private Git source registry; never log its values."""
import json
from pathlib import Path
import re


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
    """Read the required registry at the exact identity revision, never mutable main."""
    if not registry_enabled(public):
        return None
    if json.loads(values.get('PRIVATE_GITOPS_SOURCES') or '[]') != [] or values.get('PRIVATE_GITOPS_REMOVE'):
        raise ValueError('Legacy private source inputs are retired; migrate their owned registrations explicitly')
    if not isinstance(revision, str) or not re.fullmatch('[a-f0-9]{40}', revision):
        raise ValueError('Private registry requires its immutable private source revision')
    import yaml
    from playbooks.argocd.files.github_setup import repository
    from playbooks.keycloak.files.private_source import decode_contents
    document = client.request('GET', 'repos/' + repository(values['PRIVATE_CONFIG_REPOSITORY']) +
                              '/contents/platform/sources.yaml?ref=' + revision)
    if (not isinstance(document, dict) or document.get('type') != 'file' or document.get('encoding') != 'base64'
            or type(document.get('size')) is not int or not 0 <= document['size'] <= 1048576):
        raise ValueError('Private registry must be a bounded regular file')
    return validate_registry(yaml.safe_load(decode_contents(document)))


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


def verification_payload(values, public):
    """Resolve one authenticated Git revision and its complete native declarations."""
    from playbooks.argocd.files.github_app import configuration_revision
    import subprocess
    import yaml
    from urllib.parse import quote
    from playbooks.argocd.files.github_setup import repository as repository_name
    repository = values.get('PRIVATE_CONFIG_REPOSITORY')
    if not repository:
        raise ValueError('Private verification requires its designated repository')
    def read(client, revision):
        value = registry(client, values, public, revision)
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
        return {'configuration_repository': repository, 'configuration_revision': revision,
                'catalog_enabled': registry_enabled(public), 'sources': value['sources'] if value else [],
                'objects': objects, 'public_repository': public['repository'],
                'symbolic_revisions': symbolic_revisions,
                'platform_revision': public.get('privateSources', {}).get('revision')}
    return configuration_revision(values, read=read)


if __name__ == '__main__':
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

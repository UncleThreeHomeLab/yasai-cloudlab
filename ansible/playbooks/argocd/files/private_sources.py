"""Read and validate the private Git source registry; never log its values."""
import json
import copy
import hashlib
import hmac
from pathlib import Path
import re

ACCEPTANCE_PATH = 'platform/acceptance/private-sources.yaml'
ACCEPTANCE_VERSION = 'cloudlab-private-source-acceptance/v1'
CONSUMER_ACCEPTANCE_VERSION = 'cloudlab-consumer-source-acceptance/v1'


def consumer_contract(public, consumer):
    """Validate supplied context only; callers must authenticate public authority."""
    from playbooks.argocd.files.github_setup import repository
    from playbooks.argocd.files.service_activation import catalog_path
    if not isinstance(public, dict) or consumer not in ('observability', 'permissions'):
        raise ValueError('Consumer source acceptance refused')
    repository(public.get('repository'))
    if public.get('revision') != 'main': raise ValueError('Consumer source acceptance refused')
    selected = ('observability', 'services', 'identity', 'externalSecrets', 'admission') if consumer == 'observability' else ('permissions', 'identity', 'externalSecrets', 'admission')
    context = {key: copy.deepcopy(public.get(key, {})) for key in selected}
    if any(not isinstance(value, dict) for value in context.values()): raise ValueError('Consumer source acceptance refused')
    context['identity'].pop('argo', None)  # Private identity binding is separate from public input approval.
    for key, node in context.items():
        if type(node.get('enabled', False)) is not bool: raise ValueError('Consumer source acceptance refused')
    external = context['externalSecrets']
    if type(external.get('reconcile', False)) is not bool: raise ValueError('Consumer source acceptance refused')
    settings = context[consumer]
    if consumer == 'observability':
        settings = settings.get('configuration', {})
        if (not isinstance(settings, dict) or type(settings.get('enabled', False)) is not bool
                or type(settings.get('paused', False)) is not bool): raise ValueError('Consumer source acceptance refused')
        paths = [catalog_path(context['services'].get('catalogPath', catalog_path())), 'platform/observability.yaml']
    else:
        paths = ['platform/permissions.yaml']
    enabled = settings.get('enabled', False)
    if consumer == 'observability' and enabled:
        service_pin = context['services'].get('revision')
        if not isinstance(service_pin, str) or not re.fullmatch('[a-f0-9]{40}', service_pin):
            raise ValueError('Consumer source acceptance refused')
    pin, commitment = settings.get('revision', ''), settings.get('acceptanceCommitment', '')
    if (not isinstance(pin, str) or (pin and not re.fullmatch('[a-f0-9]{40}', pin))
            or not isinstance(commitment, str) or (commitment and not re.fullmatch('[a-f0-9]{64}', commitment))):
        raise ValueError('Consumer source acceptance refused')
    if enabled and (not re.fullmatch('[a-f0-9]{40}', pin) or not re.fullmatch('[a-f0-9]{64}', commitment)
            or context['identity'].get('enabled') is not True or external.get('enabled') is not True or external.get('reconcile') is not True
            or (consumer == 'observability' and context['observability'].get('enabled') is not True)
            or (consumer == 'permissions' and context['admission'].get('enabled') is not True)):
        raise ValueError('Consumer source acceptance refused')
    context.update(repository=public['repository'], revision=public['revision'])
    return {'version': CONSUMER_ACCEPTANCE_VERSION, 'consumer': consumer, 'enabled': enabled,
        'receiptPath': 'platform/acceptance/' + consumer + '.yaml', 'paths': paths,
        'acceptanceCommitment': commitment, 'context': context}


def validate_consumer_acceptance(receipt, repository, contract):
    """Check a finite consumer proof; supplied contracts alone grant no authority."""
    from playbooks.argocd.files.github_setup import repository as repository_name
    from playbooks.argocd.files.service_activation import catalog_path
    try:
        repository_name(repository)
        consumer = contract['consumer']
        paths = contract['paths']
        expected_paths = ([catalog_path(paths[0]), 'platform/observability.yaml'] if consumer == 'observability'
            else ['platform/permissions.yaml'] if consumer == 'permissions' else None)
        if (set(contract) != {'version', 'consumer', 'enabled', 'receiptPath', 'paths', 'acceptanceCommitment', 'context'}
                or contract['version'] != CONSUMER_ACCEPTANCE_VERSION or contract['enabled'] is not True
                or contract['receiptPath'] != 'platform/acceptance/' + consumer + '.yaml'
                or not isinstance(paths, list) or paths != expected_paths or any(not isinstance(path, str) for path in paths)
                or not isinstance(receipt, dict) or set(receipt) != {'version', 'consumer', 'paths', 'revision', 'nonce'}
                or any(not isinstance(receipt.get(key), str) for key in ('version', 'consumer', 'revision', 'nonce'))
                or receipt['version'] != CONSUMER_ACCEPTANCE_VERSION or receipt['consumer'] != consumer
                or not isinstance(receipt['paths'], list) or receipt['paths'] != paths
                or any(not isinstance(path, str) for path in receipt['paths'])
                or not re.fullmatch('[a-f0-9]{40}', receipt['revision']) or not re.fullmatch('[a-f0-9]{64}', receipt['nonce'])
                or not isinstance(contract['acceptanceCommitment'], str) or not re.fullmatch('[a-f0-9]{64}', contract['acceptanceCommitment'])):
            raise ValueError()
        preimage = '\n'.join([CONSUMER_ACCEPTANCE_VERSION, consumer, repository, str(len(paths)), *paths, receipt['revision'], receipt['nonce'], ''])
        if not hmac.compare_digest(hashlib.sha256(preimage.encode()).hexdigest(), contract['acceptanceCommitment']): raise ValueError()
    except (KeyError, IndexError, TypeError, ValueError, RuntimeError):
        raise ValueError('Consumer source acceptance refused') from None


def accepted_consumer(client, repository, head, public, consumer):
    """Read a strict receipt against supplied context, never authenticate that context."""
    contract = consumer_contract(public, consumer)
    if not contract['enabled']: return None
    import base64
    import yaml
    from playbooks.argocd.files.github_setup import repository as repository_name
    from playbooks.data.files.native import PrivateLoader
    try:
        if not isinstance(head, str) or not re.fullmatch('[a-f0-9]{40}', head): raise ValueError()
        path = contract['receiptPath']
        document = client.request('GET', 'repos/' + repository_name(repository) + '/contents/' + path + '?ref=' + head)
        if (not isinstance(document, dict) or document.get('type') != 'file' or document.get('path') != path
                or document.get('encoding') != 'base64' or type(document.get('size')) is not int or not 0 < document['size'] <= 4096
                or not isinstance(document.get('content'), str) or len(document['content']) > 8192): raise ValueError()
        raw = base64.b64decode(document['content'].replace('\n', '').replace('\r', ''), validate=True)
        if (len(raw) != document['size'] or hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() != document.get('sha')): raise ValueError()
        receipt = yaml.load(raw, Loader=PrivateLoader)
        validate_consumer_acceptance(receipt, repository, contract)
        return {'acceptanceCommitment': contract['acceptanceCommitment'], 'acceptedRevision': receipt['revision'], 'acceptanceReceipt': receipt}
    except Exception:
        raise ValueError('Consumer source acceptance refused') from None


def acceptance_commitment(public):
    value = public.get('privateSources', {}).get('acceptanceCommitment', '')
    if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{64}', value):
        raise ValueError('Enabled private sources require a reviewed acceptance commitment')
    return value


def validate_acceptance(receipt, repository, expected):
    if (not isinstance(receipt, dict) or set(receipt) != {'version', 'consumer', 'revision', 'nonce'}
            or any(not isinstance(value, str) for value in receipt.values())
            or receipt['version'] != ACCEPTANCE_VERSION or receipt['consumer'] != 'private-sources'
            or not re.fullmatch('[a-f0-9]{40}', receipt['revision']) or not re.fullmatch('[a-f0-9]{64}', receipt['nonce'])
            or not isinstance(expected, str) or not re.fullmatch('[a-f0-9]{64}', expected)):
        raise ValueError('Private source acceptance refused')
    preimage = '\n'.join([receipt['version'], receipt['consumer'], repository, 'platform/sources.yaml', receipt['revision'], receipt['nonce'], ''])
    if not hmac.compare_digest(hashlib.sha256(preimage.encode()).hexdigest(), expected):
        raise ValueError('Private source acceptance refused')


def accepted_source(client, repository, head, public):
    """Authenticate one private receipt; never replace approval with a live child SHA."""
    if not registry_enabled(public): return None
    import yaml
    from playbooks.keycloak.files.private_source import decode_contents
    from playbooks.argocd.files.github_setup import repository as repository_name
    expected = acceptance_commitment(public)
    class ReceiptLoader(yaml.SafeLoader):
        def compose_node(self, parent, index):
            if self.check_event(yaml.AliasEvent): raise ValueError('Private source acceptance refused')
            return super().compose_node(parent, index)
        def construct_mapping(self, node, deep=False):
            pairs = self.construct_pairs(node, deep=deep)
            if any(not isinstance(key, str) for key, _ in pairs) or len(dict(pairs)) != len(pairs):
                raise ValueError('Private source acceptance refused')
            return dict(pairs)
    try:
        if not isinstance(head, str) or not re.fullmatch('[a-f0-9]{40}', head): raise ValueError()
        document = client.request('GET', 'repos/' + repository_name(repository) + '/contents/' + ACCEPTANCE_PATH + '?ref=' + head)
        if document.get('type') != 'file' or type(document.get('size')) is not int or not 0 < document['size'] <= 4096:
            raise ValueError()
        receipt = yaml.load(decode_contents(document), Loader=ReceiptLoader)
        validate_acceptance(receipt, repository, expected)
        return {'acceptanceCommitment': expected, 'acceptedRevision': receipt['revision'], 'acceptanceReceipt': receipt}
    except Exception:
        raise ValueError('Private source acceptance refused') from None


def acceptance_spec(public, repository, revision, *, files=None):
    """Capture the reviewed native contract directly from its owning Root chart."""
    from playbooks.data.files.native import render_objects
    values = copy.deepcopy(public)
    values.setdefault('identity', {}).update(enabled=True, argo={'valuesRepository': repository, 'valuesRevision': revision})
    chart = Path(__file__).resolve().parents[4] / 'gitops/roots/public'
    if files is None:
        files = {path.relative_to(chart).as_posix(): path.read_bytes() for path in chart.rglob('*') if path.is_file()}
    sets = [obj for obj in render_objects(files, [values]) if obj['kind'] == 'ApplicationSet'
        and obj['metadata']['name'] == 'cloudlab-private-sources']
    if len(sets) != 1: raise ValueError('Private source acceptance declaration is missing')
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


def registry(client, values, public, revision, *, acceptance=None):
    """Read the complete registry only at its independently approved artifact revision."""
    if not registry_enabled(public):
        return None
    expected = acceptance_commitment(public)
    if not isinstance(acceptance, dict) or acceptance.get('acceptanceCommitment') != expected or acceptance.get('acceptedRevision') != revision:
        raise ValueError('Private source registry requires its accepted immutable revision')
    validate_acceptance(acceptance.get('acceptanceReceipt'), values['PRIVATE_CONFIG_REPOSITORY'], expected)
    if acceptance['acceptanceReceipt']['revision'] != revision:
        raise ValueError('Private source registry requires its accepted immutable revision')
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
    """Authenticate the receipt head and render only its approved immutable catalog."""
    if registry_enabled(public): acceptance_commitment(public)
    from playbooks.argocd.files.github_app import configuration_revision
    import subprocess
    import yaml
    from urllib.parse import quote
    from playbooks.argocd.files.github_setup import repository as repository_name
    repository = values.get('PRIVATE_CONFIG_REPOSITORY')
    if not repository:
        raise ValueError('Private verification requires its designated repository')
    def read(client, revision):
        enabled = registry_enabled(public)
        acceptance = accepted_source(client, repository, revision, public) if enabled else None
        value = registry(client, values, public, acceptance['acceptedRevision'], acceptance=acceptance) if enabled else None
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
                'platform_revision': public.get('privateSources', {}).get('revision')}
        if enabled:
            result.update(acceptance, applicationSet=acceptance_spec(public, repository, revision))
        return result
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

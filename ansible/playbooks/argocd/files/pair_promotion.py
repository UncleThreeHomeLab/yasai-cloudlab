"""Promote consumer acceptance pairs: private receipt PR, then public commitment PR.

Operator-run promotion for one consumer acceptance pair. It mints the private
receipt over the reviewed private revision, opens the private PR, and once the
owner merges it, re-reads the merged receipt, recomputes the commitment, and
opens the public PR recording that commitment. The owner merges both PRs; this
automation never merges. Reports JSON to stdout only.
"""
import base64
import copy
from contextlib import contextmanager
import hashlib
import json
import os
import re
import secrets
import sys
import time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = next((parent for parent in HERE.parents
             if (parent / 'platform').is_dir() and (parent / 'ansible').is_dir()), None)
if ROOT is None:
    raise RuntimeError('Pair promotion requires the CloudLab checkout')
sys.path.insert(0, str(ROOT / 'ansible'))

try:
    from playbooks.argocd.files.github_app import app_token
    from playbooks.argocd.files.github_setup import GitHub, repository
    from playbooks.argocd.files.private_sources import CONSUMER_ACCEPTANCE_VERSION, commitment_receipt
    from playbooks.secrets.files.vault import fields
except ImportError:
    from github_app import app_token
    from github_setup import GitHub, repository
    from private_sources import CONSUMER_ACCEPTANCE_VERSION, commitment_receipt
    from vault import fields

import yaml

PRIVATE_ITEM = 'github-release-private'
PUBLIC_ITEM = 'github-release-public'
APP_FIELDS = ('APP_ID', 'INSTALLATION_ID', 'PRIVATE_KEY')
APP_PERMISSIONS = {'contents': 'write', 'pull_requests': 'write', 'metadata': 'read'}
TOKEN_PERMISSIONS = {'contents': 'write', 'pull_requests': 'write'}
TOKEN_ECHO = {'contents': 'write', 'pull_requests': 'write', 'metadata': 'read'}
SUPPORTED = ('observability', 'permissions', 'services', 'previews')
VALUES_ATTRS = {'observability': ('observability', 'configuration', 'acceptanceCommitment'),
                'permissions': ('permissions', 'acceptanceCommitment'),
                'services': ('services', 'acceptanceCommitment'),
                'previews': ('previews', 'configuration', 'acceptanceCommitment')}
VALUES_PATH = 'gitops/roots/public/values.yaml'
MAX_VALUES_BYTES = 65536
MAX_RECEIPT_BYTES = 4096
SHA = re.compile(r'[a-f0-9]{40}')
NONCE = re.compile(r'[a-f0-9]{64}')


def fail(message):
    raise ValueError(message)


def branch_name(base, consumer, revision):
    """Nonce-excluding deterministic branch so retries converge on one PR pair."""
    if not SHA.fullmatch(base or '') or not SHA.fullmatch(revision or '') or consumer not in SUPPORTED:
        fail('Promotion requires a supported consumer and immutable 40-hex revisions')
    digest = hashlib.sha256((base + consumer + revision).encode()).hexdigest()[:12]
    return 'acceptance/' + consumer + '/' + digest


def release_app(item, repo):
    """Validated release App API with exact-dict grant verification for this item."""
    credentials = fields(item, APP_FIELDS)
    api = GitHub(app_token(credentials))
    app = api.request('GET', 'app')
    installation = api.request('GET', 'app/installations/' + credentials['INSTALLATION_ID'])
    owner = repo.split('/')[0].lower()
    account = installation.get('account') or {} if isinstance(installation, dict) else {}
    if (not isinstance(app, dict) or not isinstance(installation, dict) or
            str(app.get('id')) != credentials['APP_ID'] or app.get('permissions') != APP_PERMISSIONS or
            str(installation.get('app_id')) != credentials['APP_ID'] or
            installation.get('permissions') != APP_PERMISSIONS or installation.get('suspended_at') or
            installation.get('repository_selection') != 'selected' or
            (account.get('login') or '').lower() != owner or
            installation.get('target_type') != 'Organization'):
        raise RuntimeError('Release App grants differ from the designated repository contract')
    return api, credentials['INSTALLATION_ID']


def revoke(lease):
    try:
        GitHub(lease['token']).request('DELETE', 'installation/token')
    except RuntimeError as error:
        # An expired or already revoked installation token has no remaining access.
        if 'HTTP 401' not in str(error):
            raise


def single_use_token(api, repo, installation_id, *, private):
    """Single-use promotion PR token; never delivered, revoked by the caller."""
    issued = api.request('POST', 'app/installations/' + installation_id + '/access_tokens',
                         {'repositories': [repo.split('/')[1]], 'permissions': dict(TOKEN_PERMISSIONS)})
    token = issued.get('token')
    valid = isinstance(token, str) and token and not any(char in token for char in '\n\r')
    try:
        if not valid:
            raise ValueError('Issued promotion token is invalid')
        instant = datetime.fromisoformat(str(issued.get('expires_at', '')).replace('Z', '+00:00'))
        expires = int(instant.timestamp())
        if (instant.tzinfo is None or not 0 < expires - int(time.time()) <= 3660 or
                issued.get('permissions') != TOKEN_ECHO):
            raise ValueError('Issued promotion token lifetime or permissions differ')
        inventory = GitHub(token).request('GET', 'installation/repositories?per_page=100')
        rows = inventory.get('repositories', [])
        if (inventory.get('total_count') != 1 or len(rows) != 1 or rows[0].get('full_name') != repo or
                rows[0].get('private') is not private or type(rows[0].get('id')) is not int or rows[0]['id'] < 1 or
                any(rows[0].get(key) for key in ('fork', 'archived', 'disabled'))):
            raise ValueError('Issued promotion token selection differs')
        return token
    except Exception:
        if valid:
            revoke({'token': token})
        raise RuntimeError('Promotion token validation failed; private diagnostics withheld') from None


@contextmanager
def guarded(side, stage):
    """Fail closed on transport auth failures; revoke alone tolerates a dead token."""
    try:
        yield
    except Exception as error:
        # Status-matched (not class-matched): sibling imports may duplicate the transport class.
        if getattr(error, 'status', None) == 401:
            raise RuntimeError(side + ' promotion credentials rejected at ' + stage +
                               '; verify the release App installation') from None
        if getattr(error, 'status', None) == 403:
            raise RuntimeError(side + ' promotion grant refused at ' + stage +
                               '; verify the release App repository selection') from None
        raise


def dump_receipt(receipt):
    raw = yaml.safe_dump(receipt, sort_keys=True, width=4096).encode()
    if len(raw) > MAX_RECEIPT_BYTES:
        fail('Promotion receipt exceeds its bound')
    return raw


def load_receipt(raw, consumer):
    """Strict consumer receipt shape; shared by the existing-branch and merged reads."""
    try:
        receipt = yaml.safe_load(raw)
    except yaml.YAMLError:
        fail('Promotion receipt is not valid YAML')
    paths = receipt.get('paths') if isinstance(receipt, dict) else None
    if (not isinstance(receipt, dict) or set(receipt) != {'version', 'consumer', 'paths', 'revision', 'nonce'}
            or receipt['version'] != CONSUMER_ACCEPTANCE_VERSION or receipt['consumer'] != consumer
            or not isinstance(paths, list) or not 1 <= len(paths) <= 8
            or any(not isinstance(path, str) or len(path) > 256 for path in paths)
            or not SHA.fullmatch(receipt.get('revision') or '') or not NONCE.fullmatch(receipt.get('nonce') or '')):
        fail('Promotion receipt differs from its fixed shape')
    return receipt


def recompute(repository_url, receipt):
    """Recompute a consumer commitment with the same preimage join as minting."""
    paths = receipt['paths']
    preimage = '\n'.join([receipt['version'], receipt['consumer'], repository_url,
                          str(len(paths)), *paths, receipt['revision'], receipt['nonce'], ''])
    return hashlib.sha256(preimage.encode()).hexdigest()


def head_of(writer, repo):
    main = writer.request('GET', 'repos/' + repo + '/git/ref/heads/main')
    sha = main.get('object', {}).get('sha') if isinstance(main, dict) else None
    if not SHA.fullmatch(sha or ''):
        fail('Promotion base ref is invalid')
    return sha


def existing_pull(writer, repo, branch, head):
    query = 'head=' + repo.split('/')[0] + ':' + branch + '&base=main&state=all&per_page=100'
    pulls = writer.request('GET', 'repos/' + repo + '/pulls?' + query)
    if not isinstance(pulls, list) or len(pulls) > 100:
        fail('Promotion PR listing is invalid')
    if len(pulls) > 1 or pulls and (pulls[0].get('state') not in ('open', 'closed')
                                   or pulls[0].get('head', {}).get('sha') != head
                                   or pulls[0].get('base', {}).get('ref') != 'main' or type(pulls[0].get('number')) is not int):
        fail('Existing promotion PR differs; no PR changed')
    return pulls[0] if pulls else None


def ref_sha(ref):
    sha = ref.get('object', {}).get('sha') if isinstance(ref, dict) else None
    if not SHA.fullmatch(sha or ''):
        fail('Promotion branch ref is invalid')
    return sha


def created_sha(stored, what):
    sha = stored.get('commit', {}).get('sha') if isinstance(stored, dict) else None
    if not SHA.fullmatch(sha or ''):
        fail('Promotion ' + what + ' write is invalid')
    return sha


def pull_number(pull):
    if not isinstance(pull, dict) or type(pull.get('number')) is not int or pull['number'] < 1:
        fail('Promotion PR creation is invalid')
    return pull['number']


def file_at(writer, repo, path, ref, *, missing=False):
    document = writer.request('GET', 'repos/' + repo + '/contents/' + path + '?ref=' + ref, missing=missing)
    if document is None:
        return None, None
    if (not isinstance(document, dict) or document.get('type') != 'file' or document.get('encoding') != 'base64'
            or not isinstance(document.get('sha'), str) or not isinstance(document.get('content'), str)):
        fail('Promotion file read is invalid')
    return base64.b64decode(''.join(document['content'].split()), validate=True), document['sha']


def transcribe(raw, attrs, commitment):
    """Replace only the consumer acceptance commitment, preserving every other byte."""
    if not NONCE.fullmatch(commitment or '') or len(raw) > MAX_VALUES_BYTES:
        fail('Public values transcription refused')
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError('Public values transcription refused') from None
    if '\r' in text or '\t' in text or not text.endswith('\n'):
        fail('Public values transcription refused')
    try:
        old = yaml.safe_load(text)
    except yaml.YAMLError:
        raise ValueError('Public values transcription refused') from None
    lines = text.split('\n')
    start = next((index + 1 for index, line in enumerate(lines) if line == attrs[0] + ':'), None)
    if start is None:
        fail('Public values transcription refused')
    end = next((index for index in range(start, len(lines))
                if lines[index] and not lines[index].startswith((' ', '#'))), len(lines))
    if len(attrs) == 3:
        nested = next((index + 1 for index in range(start, end) if lines[index] == '  ' + attrs[1] + ':'), None)
        if nested is None:
            fail('Public values transcription refused')
        end = next((index for index in range(nested, end)
                    if re.fullmatch(r'  \S.*', lines[index] or ' ')), end)
        start = nested
    pattern = r"(\s*acceptanceCommitment:\s*)(['\"]?)[a-f0-9]{64}\2(\s*(?:#.*)?)"
    found = [index for index in range(start, end) if re.fullmatch(pattern, lines[index])]
    if len(found) != 1:
        fail('Public values transcription refused')
    match = re.fullmatch(pattern, lines[found[0]])
    quote = match.group(2)
    if yaml.safe_load(quote + commitment + quote) != commitment:
        quote = "'"  # An all-digit commitment stays a string only when quoted.
    lines[found[0]] = match.group(1) + quote + commitment + quote + match.group(3)
    revised = '\n'.join(lines)
    try:
        new = yaml.safe_load(revised)
    except yaml.YAMLError:
        raise ValueError('Public values transcription refused') from None
    expected = copy.deepcopy(old)
    try:
        node = expected
        for key in attrs[:-1]:
            node = node[key]
        if not isinstance(node.get(attrs[-1]), str):
            fail('Public values transcription refused')
        node[attrs[-1]] = commitment
    except (KeyError, TypeError, AttributeError):
        raise ValueError('Public values transcription refused') from None
    if new != expected:
        fail('Public values transcription refused')
    return revised.encode()


def promote_private(consumer, private_repository, base, revision, nonce=None, catalog='services/catalog.json'):
    """Adopt the merged receipt when present, else mint it and open the private PR."""
    if consumer not in SUPPORTED:
        fail('Unsupported promotion consumer')
    repository(private_repository)
    if not SHA.fullmatch(base or '') or not SHA.fullmatch(revision or ''):
        fail('Promotion requires immutable 40-hex revisions')
    if nonce is not None and not NONCE.fullmatch(nonce):
        fail('Promotion requires a fresh 64-hex nonce')
    private = repository(private_repository)
    with guarded('Private', 'grant verification'):
        api, installation_id = release_app(PRIVATE_ITEM, private)
    with guarded('Private', 'token issuance'):
        token = single_use_token(api, private, installation_id, private=True)
    try:
        with guarded('Private', 'receipt promotion'):
            writer = GitHub(token)
            if head_of(writer, private) != base:
                fail('Reviewed private base is stale; refresh before promoting')
            _, shape, path = commitment_receipt(consumer, private_repository, revision, '0' * 64, catalog)
            merged, _ = file_at(writer, private, path, base, missing=True)
            if nonce is None and merged is not None:
                try:
                    adopted = load_receipt(merged, consumer)
                except ValueError:
                    adopted = None
                if adopted is not None and all(adopted[key] == shape[key]
                                               for key in ('version', 'consumer', 'paths', 'revision')):
                    return {'branch': None, 'proposed': False, 'pr': None, 'merged': True,
                            'adopted': True, 'commitment': recompute(private_repository, adopted),
                            'grantsVerified': True}
            branch = branch_name(base, consumer, revision)
            ref = writer.request('GET', 'repos/' + private + '/git/ref/heads/' + branch, missing=True)
            if ref is None:
                picked = nonce or secrets.token_hex(32)
                commitment, receipt, _ = commitment_receipt(
                    consumer, private_repository, revision, picked, catalog)
                intended = dump_receipt(receipt)
                writer.request('POST', 'repos/' + private + '/git/refs', {'ref': 'refs/heads/' + branch, 'sha': base})
                _, sha = file_at(writer, private, path, base, missing=True)
                stored = writer.request('PUT', 'repos/' + private + '/contents/' + path,
                                        {'message': 'Promote ' + consumer + ' acceptance receipt',
                                         'content': base64.b64encode(intended).decode(), 'branch': branch,
                                         **({'sha': sha} if sha else {})})
                head = created_sha(stored, 'receipt')
            else:
                head = ref_sha(ref)
                current, _ = file_at(writer, private, path, branch)
                if current is None:
                    fail('Existing promotion branch differs; overwrite refused')
                existing = load_receipt(current, consumer)
                if (nonce is not None and existing['nonce'] != nonce) or any(
                        existing[key] != shape[key] for key in ('version', 'consumer', 'paths', 'revision')):
                    fail('Existing promotion branch differs; overwrite refused')
                commitment, receipt, _ = commitment_receipt(
                    consumer, private_repository, revision, existing['nonce'], catalog)
                intended = dump_receipt(receipt)
                if current != intended:
                    fail('Existing promotion branch differs; overwrite refused')
            pull = existing_pull(writer, private, branch, head)
            proposed = pull is None
            if proposed:
                pull = writer.request('POST', 'repos/' + private + '/pulls', {
                    'base': 'main', 'head': branch, 'title': 'Promote ' + consumer + ' acceptance receipt',
                    'body': 'Promote the ' + consumer + ' acceptance receipt over the reviewed revision. ' +
                            'Only that file changes. The owner merges; this automation never merges.\n'})
                pull_number(pull)
            detail = writer.request('GET', 'repos/' + private + '/pulls/' + str(pull['number']))
            if not isinstance(detail, dict):
                fail('Promotion PR detail is invalid')
            if detail.get('merged') is True:
                merged, _ = file_at(writer, private, path, 'main')
                if merged is None:
                    fail('Merged receipt differs from the promoted pair; no public PR opened')
                receipt = load_receipt(merged, consumer)
                if merged != intended or recompute(private_repository, receipt) != commitment:
                    fail('Merged receipt differs from the promoted pair; no public PR opened')
                return {'branch': branch, 'proposed': proposed, 'pr': pull['number'],
                        'merged': True, 'adopted': False, 'commitment': commitment, 'grantsVerified': True}
            if detail.get('state') != 'open' or detail.get('merged') is not False:
                fail('Promotion PR was closed unmerged; owner action required')
            return {'branch': branch, 'proposed': proposed, 'pr': pull['number'],
                    'merged': False, 'adopted': False, 'commitment': commitment, 'grantsVerified': True}
    finally:
        revoke({'token': token})


def promote_public(consumer, public_repository, base, revision, commitment):
    """Open the public commitment PR over the reviewed public base (owner merges)."""
    if consumer not in SUPPORTED:
        fail('Unsupported promotion consumer')
    repository(public_repository)
    if not SHA.fullmatch(base or '') or not NONCE.fullmatch(commitment or ''):
        fail('Public promotion requires an immutable base and a 64-hex commitment')
    public = repository(public_repository)
    # Public-App grant verification mirrors the trusted issuance in github_app.py:104:
    # the repositories selection plus exact contents/pull_requests permissions are
    # checked live against the installation and the issued token below.
    with guarded('Public', 'grant verification'):
        api, installation_id = release_app(PUBLIC_ITEM, public)
    with guarded('Public', 'token issuance'):
        token = single_use_token(api, public, installation_id, private=False)
    try:
        with guarded('Public', 'commitment promotion'):
            writer = GitHub(token)
            if head_of(writer, public) != base:
                fail('Reviewed public base is stale; refresh before promoting')
            branch = branch_name(base, consumer, revision)
            raw, _ = file_at(writer, public, VALUES_PATH, base)
            if raw is None:
                fail('Public values are missing at the reviewed base')
            intended = transcribe(raw, VALUES_ATTRS[consumer], commitment)
            if intended == raw:
                return {'branch': None, 'proposed': False, 'pr': None,
                        'unchanged': True, 'grantsVerified': True}
            ref = writer.request('GET', 'repos/' + public + '/git/ref/heads/' + branch, missing=True)
            if ref is None:
                writer.request('POST', 'repos/' + public + '/git/refs', {'ref': 'refs/heads/' + branch, 'sha': base})
                _, sha = file_at(writer, public, VALUES_PATH, base)
                stored = writer.request('PUT', 'repos/' + public + '/contents/' + VALUES_PATH,
                                        {'message': 'Promote ' + consumer + ' acceptance commitment',
                                         'content': base64.b64encode(intended).decode(), 'branch': branch, 'sha': sha})
                head = created_sha(stored, 'values')
            else:
                head = ref_sha(ref)
                current, _ = file_at(writer, public, VALUES_PATH, branch)
                if current != intended:
                    fail('Existing promotion branch differs; overwrite refused')
            pull = existing_pull(writer, public, branch, head)
            proposed = pull is None
            if proposed:
                pull = writer.request('POST', 'repos/' + public + '/pulls', {
                    'base': 'main', 'head': branch, 'title': 'Promote ' + consumer + ' acceptance commitment',
                    'body': 'Record the reviewed ' + consumer + ' acceptance commitment. ' +
                            'Only that value changes. The owner merges; this automation never merges.\n'})
                pull_number(pull)
            return {'branch': branch, 'proposed': proposed, 'pr': pull['number'],
                    'unchanged': False, 'grantsVerified': True}
    finally:
        revoke({'token': token})


def promote(consumer, private_repository, public_repository, private_base, public_base, revision,
            nonce=None, catalog='services/catalog.json'):
    """Promote one pair; the public PR follows only its merged private receipt."""
    if repository(private_repository).lower() == repository(public_repository).lower():
        fail('Promotion requires distinct private and public repositories')
    private = promote_private(consumer, private_repository, private_base, revision, nonce, catalog)
    if not private['merged']:
        return {'consumer': consumer, 'commitment': private['commitment'],
                'private': private, 'public': None}
    public = promote_public(consumer, public_repository, public_base, revision, private['commitment'])
    return {'consumer': consumer, 'commitment': private['commitment'],
            'private': private, 'public': public}


def parse_arguments(argv):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='promote', choices=('promote',))
    parser.add_argument('--consumer', required=True, choices=SUPPORTED)
    parser.add_argument('--private-repo', required=True)
    parser.add_argument('--public-repo', required=True)
    parser.add_argument('--private-base', required=True)
    parser.add_argument('--public-base', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--catalog-path', default='services/catalog.json')
    parser.add_argument('--nonce', default=None)
    parser.add_argument('--workspace', default='/workspace')
    return parser.parse_args(argv)


def main(argv=None):
    arguments = parse_arguments(argv if argv is not None else sys.argv[1:])
    from dotenv import dotenv_values
    values = dotenv_values(str(Path(arguments.workspace) / '.env'), interpolate=False)
    if values.get('OP_SERVICE_ACCOUNT_TOKEN'):
        os.environ.setdefault('OP_SERVICE_ACCOUNT_TOKEN', values['OP_SERVICE_ACCOUNT_TOKEN'])
    try:
        report = promote(arguments.consumer, arguments.private_repo, arguments.public_repo,
                         arguments.private_base, arguments.public_base, arguments.revision,
                         arguments.nonce, arguments.catalog_path)
        report['completedAt'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        print(json.dumps(report, sort_keys=True), flush=True)
        return 0
    except (RuntimeError, ValueError, OSError) as error:
        print('pair promotion: ' + str(error), file=sys.stderr, flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

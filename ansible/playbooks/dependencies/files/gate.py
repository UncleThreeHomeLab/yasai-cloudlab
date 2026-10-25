"""Draft-first GitHub writes and receipts bound to the final verified head."""
import base64
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import time

from .security import digest, relative

SHA = re.compile(r'[a-f0-9]{40}')
BRANCH = re.compile(r'cloudlab-maintenance/[a-z0-9][a-z0-9-]{0,79}')


def branch_prefix(base):
    return 'cloudlab-maintenance/' + digest(base.encode())[:12] + '-'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


class Gate:
    """Control storage must never be mounted in a candidate execution container."""

    def __init__(self, api, scope, control):
        required = {'repository', 'repositoryId', 'requester', 'base', 'branchPrefix'}
        if (set(scope) != required or type(scope['repositoryId']) is not int or
                scope['repositoryId'] < 1 or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', scope['repository']) or
                not re.fullmatch(r'[A-Za-z0-9-]+\[bot\]', scope['requester']) or
                not re.fullmatch(r'(main|cloudlab-maintenance-fixture/[a-z0-9-]{1,64})', scope['base']) or
                scope['branchPrefix'] != branch_prefix(scope['base'])):
            raise ValueError('Maintenance requires an exact public repository and owned requester scope')
        self.api, self.scope, self.control = api, dict(scope), Path(control)
        self.control.mkdir(mode=0o700, parents=True, exist_ok=True)
        secret = self.control / 'receipt-key'
        if not secret.exists():
            with secret.open('xb') as stream:
                stream.write(secrets.token_bytes(32))
            secret.chmod(0o600)
        self.key = secret.read_bytes()
        if len(self.key) != 32:
            raise ValueError('Invalid trusted receipt key')

    @property
    def repository(self):
        return 'repos/' + self.scope['repository']

    def identity(self):
        row = self.api.request('GET', self.repository)
        if (row.get('id') != self.scope['repositoryId'] or row.get('full_name') != self.scope['repository'] or
                row.get('private') is not False or row.get('fork') or row.get('archived') or row.get('disabled')):
            raise ValueError('Maintenance repository identity changed')

    def current(self, number, *, fresh_base=True):
        if type(number) is not int or number < 1:
            raise ValueError('Invalid maintenance pull request number')
        self.identity()
        row = self.api.request('GET', self.repository + '/pulls/' + str(number))
        if (row.get('state') != 'open' or row.get('merged') or
                row.get('user', {}).get('login') != self.scope['requester'] or
                row.get('user', {}).get('type') != 'Bot' or
                row.get('head', {}).get('repo', {}).get('id') != self.scope['repositoryId'] or
                row.get('base', {}).get('repo', {}).get('id') != self.scope['repositoryId'] or
                row['base'].get('ref') != self.scope['base'] or
                not BRANCH.fullmatch(row['head'].get('ref', '')) or
                not row['head']['ref'].startswith(self.scope['branchPrefix']) or
                not SHA.fullmatch(row['head'].get('sha', '')) or
                not SHA.fullmatch(row['base'].get('sha', ''))):
            raise ValueError('Pull request is outside the owned maintenance scope')
        if fresh_base:
            base = self.api.request('GET', self.repository + '/git/ref/heads/' + self.scope['base'])
            if base.get('object', {}).get('sha') != row['base']['sha']:
                raise ValueError('Maintenance base changed; refresh the draft')
        return row

    def invalidate(self, number):
        if type(number) is not int or number < 1:
            raise ValueError('Invalid maintenance pull request number')
        (self.control / (str(number) + '.json')).unlink(missing_ok=True)

    def redraft(self, number):
        self.invalidate(number)
        row = self.current(number, fresh_base=False)
        if not row.get('draft'):
            self.api.request('POST', 'graphql', {
                'query': 'mutation($id:ID!){convertPullRequestToDraft(input:{pullRequestId:$id}){pullRequest{isDraft}}}',
                'variables': {'id': row['node_id']}})
        current = self.current(number, fresh_base=False)
        if not current.get('draft'):
            raise ValueError('Cannot confirm maintenance draft; writes refused')
        return current

    def prepare_write(self):
        """Every bot-write invocation first invalidates and drafts every owned PR."""
        self.identity()
        rows = self.api.request('GET', self.repository + '/pulls?state=open&per_page=100')
        if len(rows) >= 100:
            raise ValueError('Maintenance pull request inventory requires explicit pagination')
        owned = [row for row in rows if
                 row.get('user', {}).get('login') == self.scope['requester'] and
                 BRANCH.fullmatch(row.get('head', {}).get('ref', '')) and
                 row['head']['ref'].startswith(self.scope['branchPrefix']) and
                 row.get('base', {}).get('ref') == self.scope['base']]
        # Invalidate all receipts even if an earlier conversion fails.
        for row in owned:
            self.invalidate(row['number'])
        return [self.redraft(row['number']) for row in owned]

    def stamp(self, number, evidence):
        row = self.current(number)
        required = {'head', 'base', 'candidateTree', 'pinset', 'helpers', 'toolchain', 'checks'}
        if (not row.get('draft') or set(evidence) != required or
                evidence['head'] != row['head']['sha'] or evidence['base'] != row['base']['sha'] or
                not evidence['checks'] or any(value != 'PASS' for value in evidence['checks'].values()) or
                not evidence['toolchain'] or any(not re.fullmatch(r'.+@sha256:[a-f0-9]{64}', image)
                                                  for image in evidence['toolchain']) or
                any(not re.fullmatch(r'[a-f0-9]{64}', evidence[name]) for name in
                    ('candidateTree', 'pinset', 'helpers'))):
            raise ValueError('Verification evidence differs from the final published draft')
        body = {'scope': self.scope, 'number': number, 'verifiedAt': int(time.time()), **evidence}
        document = {'body': body, 'mac': hmac.new(self.key, canonical(body), hashlib.sha256).hexdigest()}
        path = self.control / (str(number) + '.json')
        path.write_bytes(canonical(document))
        path.chmod(0o600)
        return body

    def ready(self, number, expected):
        try:
            row = self.current(number)
            document = json.loads((self.control / (str(number) + '.json')).read_bytes())
            body = document['body']
            if set(expected) != {'candidateTree', 'pinset', 'helpers', 'toolchain', 'checks'}:
                raise ValueError('Readiness requires all current trusted verification inputs')
            valid = hmac.compare_digest(document['mac'], hmac.new(self.key, canonical(body), hashlib.sha256).hexdigest())
            if (not valid or body['scope'] != self.scope or body['number'] != number or
                    not row.get('draft') or body['head'] != row['head']['sha'] or body['base'] != row['base']['sha'] or
                    any(body.get(key) != value for key, value in expected.items()) or
                    not 0 <= int(time.time()) - body['verifiedAt'] <= 3600):
                raise ValueError('Maintenance receipt is stale or differs from trusted inputs')
            self.api.request('POST', 'graphql', {
                'query': 'mutation($id:ID!){markPullRequestReadyForReview(input:{pullRequestId:$id}){pullRequest{isDraft}}}',
                'variables': {'id': row['node_id']}})
            final = self.current(number)
            if final.get('draft') or final['head']['sha'] != body['head'] or final['base']['sha'] != body['base']:
                raise ValueError('Maintenance changed during readiness promotion')
        except Exception:
            self.redraft(number)
            raise
        return {'number': number, 'head': body['head'], 'ready': True}

    def publish(self, number, expected_head, expected_base, files, allowed, *, modes=None):
        self.prepare_write()
        row = self.current(number)
        if not row.get('draft') or row['head']['sha'] != expected_head or row['base']['sha'] != expected_base:
            raise ValueError('Maintenance head or base changed before publication')
        if not files or set(files) - set(allowed):
            raise ValueError('Maintenance patch contains unowned paths')
        deleted = {path for path, raw in files.items() if raw is None}
        added_archives = {path for path, raw in files.items() if raw is not None and path.endswith('.tgz') and path not in (modes or {})}
        normalize = lambda path: re.sub(r'v?[0-9]+\.[0-9]+\.[0-9]+(?=[.]tgz$)', '<version>', path)
        if (deleted and (any(not path.endswith('.tgz') or normalize(path) == path for path in deleted) or
                         sorted(map(normalize, deleted)) != sorted(map(normalize, added_archives)))):
            raise ValueError('Maintenance deletions require exact owned chart archive rename pairs')
        for path, raw in files.items():
            relative(path)
            if path.startswith('.github/workflows/'):
                raise ValueError('Release App cannot publish workflow changes')
            if raw is not None and (not isinstance(raw, bytes) or len(raw) > 256 * 1024 * 1024):
                raise ValueError('Invalid maintenance patch content')
        parent = self.api.request('GET', self.repository + '/git/commits/' + expected_head)
        tree = []
        for path, raw in sorted(files.items()):
            if raw is None:
                tree.append({'path': path, 'mode': (modes or {}).get(path, '100644'), 'type': 'blob', 'sha': None})
                continue
            blob = self.api.request('POST', self.repository + '/git/blobs',
                {'content': base64.b64encode(raw).decode(), 'encoding': 'base64'})
            mode = (modes or {}).get(path, '100644')
            if mode not in ('100644', '100755'):
                raise ValueError('Maintenance publication contains an unsupported file mode')
            tree.append({'path': path, 'mode': mode, 'type': 'blob', 'sha': blob['sha']})
        created = self.api.request('POST', self.repository + '/git/trees',
            {'base_tree': parent['tree']['sha'], 'tree': tree})
        commit = self.api.request('POST', self.repository + '/git/commits',
            {'message': 'Maintain reviewed dependency companions', 'tree': created['sha'], 'parents': [expected_head]})
        # Recheck after object creation, before the only branch mutation. force=false
        # makes a concurrent collaborator commit fail instead of overwriting it.
        current = self.current(number)
        if not current.get('draft') or current['head']['sha'] != expected_head or current['base']['sha'] != expected_base:
            raise ValueError('Maintenance changed before branch update')
        self.api.request('PATCH', self.repository + '/git/refs/heads/' + row['head']['ref'],
                         {'sha': commit['sha'], 'force': False})
        self.invalidate(number)
        final = self.current(number)
        if not final.get('draft') or final['head']['sha'] != commit['sha']:
            self.redraft(number)
            raise ValueError('Maintenance publication changed; repeat final verification')
        return {'number': number, 'head': commit['sha'], 'draft': True, 'verificationRequired': True}

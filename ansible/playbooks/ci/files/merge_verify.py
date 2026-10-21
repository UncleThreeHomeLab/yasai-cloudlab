"""Prove the release App cannot merge a bounded, non-deploying GitOps fixture."""
import json
import os
import re
import secrets
import time
import urllib.error
import urllib.request
import urllib.parse

from playbooks.argocd.files.github_app import app_token
from playbooks.argocd.files.github_setup import GitHub, configuration, inputs
from playbooks.ci.files.workflow_permissions import require_release_guard
from playbooks.infrastructure.files import harbor
from playbooks.harbor.files.recovery import atomic
from playbooks.secrets.files.vault import fields

FILE = 'verification/integration/fixtures/merge-guard-probe.json'
FIXTURE_REF = re.compile(r'ci/merge-guard-proof-[a-f0-9]{16}')


def denied(api, repository, number, head):
    request = urllib.request.Request('https://api.github.com/repos/' + repository + '/pulls/' + str(number) + '/merge',
        data=json.dumps({'sha': head, 'merge_method': 'squash'}).encode(), method='PUT',
        headers={'Authorization': 'Bearer ' + api.token, 'Accept': 'application/vnd.github+json',
                 'Content-Type': 'application/json', 'X-GitHub-Api-Version': '2022-11-28'})
    try:
        with api.opener.open(request, timeout=30):
            raise RuntimeError('Release App unexpectedly merged a non-deploying fixture; inspect its single file')
    except urllib.error.HTTPError as error:
        message = json.loads(error.read(65536)).get('message', '').lower()
        if error.code not in (403, 405) or not any(word in message for word in ('rule', 'protected', 'not allowed', 'blocked')):
            raise RuntimeError('Release merge denial was not attributable to repository policy') from None
        return error.code


def tag_rule_failed(evidence, reference, actor, ruleset, rule_type, head):
    return (evidence.get('ref') == reference and evidence.get('actor_id') == actor and evidence.get('result') == 'fail' and
            evidence.get('after_sha') == head and any(row.get('enforcement') == 'active' and row.get('result') == 'fail' and
            row.get('rule_type') == rule_type and row.get('rule_source', {}).get('type') == 'ruleset' and
            row['rule_source'].get('id') == ruleset for row in evidence.get('rule_evaluations', [])))


def tag_denied(api, repository, tag, head, method, *, operator_api, actor, ruleset):
    if not FIXTURE_REF.fullmatch(tag) or method not in ('POST', 'PATCH', 'DELETE'):
        raise ValueError('Tag authorization proof exceeds its fixture scope')
    reference = 'refs/tags/' + tag
    audits = 'repos/' + repository + '/rulesets/rule-suites'
    query = audits + '?' + urllib.parse.urlencode({'ref': reference, 'time_period': 'hour', 'per_page': 100})
    previous = {row['id'] for row in operator_api.request('GET', query)}
    path = '/git/refs' + ('' if method == 'POST' else '/tags/' + tag)
    body = {'ref': 'refs/tags/' + tag, 'sha': head} if method == 'POST' else (
        {'sha': head, 'force': True} if method == 'PATCH' else None)
    request = urllib.request.Request('https://api.github.com/repos/' + repository + path,
        data=json.dumps(body).encode() if body is not None else None, method=method,
        headers={'Authorization': 'Bearer ' + api.token, 'Accept': 'application/vnd.github+json',
                 'Content-Type': 'application/json', 'X-GitHub-Api-Version': '2022-11-28'})
    try:
        with api.opener.open(request, timeout=30):
            raise RuntimeError('Release App unexpectedly mutated a harmless proof tag')
    except urllib.error.HTTPError as error:
        message = json.loads(error.read(65536)).get('message', '').lower()
        if error.code not in (403, 422) or not any(word in message for word in (
                'rule', 'protected', 'not allowed', 'blocked', 'reference update failed')):
            raise RuntimeError('Tag mutation denial was not attributable to repository policy') from None
        status = error.code
    rule_type = {'POST': 'creation', 'PATCH': 'update', 'DELETE': 'deletion'}[method]
    after = '0' * 40 if method == 'DELETE' else head
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        for row in operator_api.request('GET', query):
            if row['id'] not in previous:
                evidence = operator_api.request('GET', audits + '/' + str(row['id']))
                if tag_rule_failed(evidence, reference, actor, ruleset, rule_type, after):
                    return status
        time.sleep(1)
    raise RuntimeError('Tag denial lacks a fresh enforced rule evaluation for this App, ref and mutation')


def cleanup(api, receipt, *, tag_api=None):
    repository, branch, head = receipt['repository'], receipt['branch'], receipt.get('head')
    if not FIXTURE_REF.fullmatch(branch) or not head:
        raise ValueError('Merge fixture cleanup scope is incomplete; receipt retained')
    prefix = 'repos/' + repository
    reference = api.request('GET', prefix + '/git/ref/heads/' + branch, missing=True)
    if reference is not None and reference['object']['sha'] != head:
        raise ValueError('Merge fixture branch changed; cleanup refused')
    if receipt.get('tag'):
        if receipt['tag'] != branch:
            raise ValueError('Tag cleanup exceeds its original fixture')
        operator = tag_api or api
        tag = operator.request('GET', prefix + '/git/ref/tags/' + branch, missing=True)
        if tag is not None:
            if tag['object']['sha'] != head:
                raise ValueError('Proof tag changed; preserve it for inspection')
            operator.request('DELETE', prefix + '/git/refs/tags/' + branch)
    pulls = api.request('GET', prefix + '/pulls?state=all&head=' + repository.split('/')[0] + ':' + branch)
    for pull in pulls:
        if pull['head']['sha'] != head or pull.get('merged_at'):
            raise ValueError('Merge fixture PR changed or merged; operator review required')
        if pull['state'] == 'open':
            api.request('PATCH', prefix + '/pulls/' + str(pull['number']), {'state': 'closed'})
    if reference is not None:
        api.request('DELETE', prefix + '/git/refs/heads/' + branch)


def prove(api, repository, receipt_path, *, operator_api):
    guards = require_release_guard(operator_api, repository)
    if receipt_path.exists():
        old = json.loads(receipt_path.read_text())
        if old['repository'] != repository:
            raise ValueError('Merge fixture recovery requires its original repository')
        cleanup(api, old, tag_api=operator_api)
        receipt_path.unlink()
    prefix = 'repos/' + repository
    base = api.request('GET', prefix + '/git/ref/heads/main')['object']['sha']
    tree = api.request('GET', prefix + '/git/commits/' + base)['tree']['sha']
    branch = 'ci/merge-guard-proof-' + secrets.token_hex(8)
    content = json.dumps({'fixture': 'release-merge-boundary', 'nonce': branch.rsplit('-', 1)[-1]}) + '\n'
    tree = api.request('POST', prefix + '/git/trees', {'base_tree': tree,
        'tree': [{'path': FILE, 'mode': '100644', 'type': 'blob', 'content': content}]})['sha']
    head = api.request('POST', prefix + '/git/commits', {
        'message': 'Verify release App merge denial', 'tree': tree, 'parents': [base]})['sha']
    receipt = {'repository': repository, 'branch': branch, 'head': head, 'tag': branch}
    atomic(receipt_path, receipt)
    try:
        api.request('POST', prefix + '/git/refs', {'ref': 'refs/heads/' + branch, 'sha': head})
        pull = api.request('POST', prefix + '/pulls', {'base': 'main', 'head': branch,
            'title': 'Verify release App merge boundary',
            'body': 'Disposable authorization fixture. Changes one non-deploying verification file; never intended to merge.'})
        comparison = api.request('GET', prefix + '/compare/' + base + '...' + head)
        if comparison['total_commits'] != 1 or [f['filename'] for f in comparison['files']] != [FILE]:
            raise ValueError('Merge fixture exceeds its single non-deploying file')
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            current = api.request('GET', prefix + '/pulls/' + str(pull['number']))
            if current.get('mergeable') is True:
                break
            time.sleep(3)
        else:
            raise RuntimeError('Merge fixture is not structurally mergeable; denial is not proven')
        status = denied(api, repository, pull['number'], head)
        audit = {'operator_api': operator_api, 'actor': pull['user']['id'], 'ruleset': guards['tag']}
        tag_denied(api, repository, branch, head, 'POST', **audit)
        operator_api.request('POST', prefix + '/git/refs', {'ref': 'refs/tags/' + branch, 'sha': head})
        tag_denied(api, repository, branch, base, 'PATCH', **audit)
        tag_denied(api, repository, branch, head, 'DELETE', **audit)
        current = api.request('GET', prefix + '/pulls/' + str(pull['number']))
        if current.get('merged') or current['state'] != 'open' or current['head']['sha'] != head:
            raise RuntimeError('Merge fixture did not remain open and unchanged')
        return {'release_app_proposed_pr': True, 'release_app_merge_denied': True,
                'denial_status': status, 'non_deploying_files': 1, 'tag_mutations_denied': 3}
    finally:
        cleanup(api, receipt, tag_api=operator_api)
        receipt_path.unlink()


def main():
    harbor.binding()
    values, reader = inputs()
    repository, = [name for role, name, private in configuration(values) if role == 'public-platform' and not private]
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    credentials = fields('github-release-public', ('APP_ID', 'INSTALLATION_ID', 'PRIVATE_KEY'))
    app = GitHub(app_token(credentials))
    target = reader.request('GET', 'repos/' + repository)
    if target.get('full_name') != repository or target.get('private') or target.get('fork') or target.get('archived'):
        raise ValueError('Merge proof requires its designated public GitOps repository')
    token = app.request('POST', 'app/installations/' + credentials['INSTALLATION_ID'] + '/access_tokens',
        {'repository_ids': [target['id']], 'permissions': {'contents': 'write', 'pull_requests': 'write'}})['token']
    client = GitHub(token)
    try:
        print(json.dumps(prove(client, repository, harbor.WORK / 'ci/merge-proof.json', operator_api=reader)))
    finally:
        client.request('DELETE', 'installation/token')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Merge authorization proof incomplete; private diagnostics withheld and recovery receipt preserved') from None

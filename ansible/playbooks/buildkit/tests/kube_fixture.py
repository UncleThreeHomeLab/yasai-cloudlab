"""Disposable Kubernetes command fixture; it never contacts a cluster."""
import json
import os
from pathlib import Path
import sys

path = Path(os.environ['BUILDKIT_TEST_STATE'])
state = json.loads(path.read_text())
args = sys.argv[2:]
document = json.load(sys.stdin) if '-f' in args else None
response, error = {}, None
state['calls'].append({'args': args, 'document': document})
if args[:2] == ['get', 'nodes']:
    response = {'items': [{'metadata': {'name': node}} for node in ('node-a', 'node-b')]}
elif args[:2] == ['get', 'jobs']:
    response = {'items': []}
elif args[:2] == ['get', 'resourcequota']:
    response = {'status': {'hard': {'pods': '1'}}}
elif args[:2] == ['get', 'job/proof']:
    if state.get('pending_polls', 0):
        state['pending_polls'] -= 1
        response = {'status': {'active': 1}}
    else:
        response = {'status': {'failed': 1}} if state.get('fail_build') else {
            'status': {'conditions': [{'type': 'Complete', 'status': 'True'}]}}
elif args[0] == 'create' and '--dry-run=server' in args:
    assert state.get('job')
    error = 'exceeded quota: build-budget'
elif args[0] == 'create':
    if document['kind'] == 'Namespace':
        assert not state.get('namespace')
        state['namespace'] = document['metadata']['name']
        response = {'metadata': {'uid': 'namespace-original'}}
    elif document['kind'] == 'Job':
        assert not state.get('job'), 'Concurrent build attempted'
        assert document['metadata']['namespace'] == state['namespace']
        state['job'] = document['spec']['template']['spec']['nodeName']
        state['build_nodes'].append(state['job'])
    else:
        assert document['kind'] == 'List'
elif args[0] == 'wait':
    assert '--for=delete' in args
elif args[0] == 'logs':
    response = 'CLOUDLAB_ROOTLESS_BUILD_OK'
elif args[:2] == ['delete', 'job/proof']:
    state.pop('job')
elif args[0] == 'delete':
    assert args[1] == '--raw=/api/v1/namespaces/' + state['namespace']
    assert document['preconditions'] == {'uid': 'namespace-original'}
    if state.get('replace_namespace'):
        error = 'Precondition failed: UID changed'
    else:
        state['namespace_deleted'] = True
        state.pop('namespace')
else:
    raise AssertionError('Unexpected Kubernetes command')
path.write_text(json.dumps(state))
if error:
    print(error, file=sys.stderr)
    raise SystemExit(1)
print(response if isinstance(response, str) else json.dumps(response))

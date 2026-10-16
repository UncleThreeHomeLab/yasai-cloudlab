"""Synthetic protected recovery metadata; no service credentials."""
import json
import copy
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
from automation.harbor.recovery import CLAIMS, SECRETS, ARTIFACTS


@contextmanager
def unsigned_registry():
    """Loopback-only missing-manifest responses for native offline signing checks."""
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            body = b'{}' if self.path == '/v2/' else b'{"errors":[{"code":"MANIFEST_UNKNOWN","message":"synthetic missing image"}]}'
            self.send_response(200 if self.path == '/v2/' else 404)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Docker-Distribution-Api-Version', 'registry/2.0')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(body)

        do_HEAD = do_GET
    with ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            yield '127.0.0.1:' + str(server.server_port)
        finally:
            server.shutdown()
            worker.join(timeout=5)


def deployment_artifacts():
    return {project: [{'digest': 'sha256:' + format(number + index * 6 + 1, '064x'),
        'payload_sha256': format(number + index * 6 + 101, '064x'),
        'payload_bytes': ((256 * 1024**2 if index == 0 else 1024**2) if number == 0 else 4096)}
        for number in range(6)] for index, project in enumerate(('cloudlab-public', 'cloudlab-private'))}


def manifest():
    generation = 'harbor-' + 'a' * 24
    return {'format': 1, 'generation': generation, 'captured': True, 'captured_at': 1790805600,
        'capture_seconds': 1, 'consistency': 'all-writers-stopped',
        'operation': 'monthly', 'installation': {'revision': 'f' * 40,
            'chart_sha256': json.loads((ARTIFACTS / 'server/artifact.lock.json').read_text())['sha256'],
            'images': sorted(json.loads((ARTIFACTS / 'images.lock.json').read_text()).values())},
        'secrets': {name: 'b' * 64 for name in SECRETS},
        'inventory': {'database_sha256': 'c' * 64, 'blobs_sha256': 'd' * 64,
                      'artifact_digests': ['sha256:' + 'e' * 64]},
        'volumes': {component: {'claim': claim, 'claim_uid': f'{number:08d}-1111-2222-3333-444444444444',
            'volume_uid': f'{number:08d}-5555-6666-7777-888888888888',
            'volume': f'pvc-{number:08d}-1111-2222-3333-444444444444', 'size': '1Gi', 'actual_bytes': 1024,
            'snapshot': generation + '-' + component} for number, (component, claim) in enumerate(CLAIMS.items())}}


def completed_api_plan(plan):
    value = copy.deepcopy(plan)
    projects = {'cloudlab-public': 11, 'cloudlab-private': 12}
    groups = {'/platform-admin': 21, '/developer': 22, '/viewer': 23}
    members = {'public_admin': 'cloudlab-public', 'public_developer': 'cloudlab-public',
               'public_viewer': 'cloudlab-public', 'private_admin': 'cloudlab-private', 'private_developer': 'cloudlab-private'}
    for number, row in enumerate(value['resource_changes'], 1):
        attributes = row['change']['after']
        key = json.loads(row['address'].split('[', 1)[1][:-1])
        kind = row['type']
        if kind == 'harbor_project':
            attributes.update(id='/projects/' + str(projects[key]), project_id=projects[key], registry_id=0)
        elif kind == 'harbor_group':
            attributes['id'] = '/usergroups/' + str(groups[key])
        elif kind == 'harbor_project_member_group':
            project_id = '/projects/' + str(projects[members[key]])
            attributes.update(id=project_id + '/members/' + str(number), project_id=project_id,
                              group_id=groups[attributes['group_name']])
        elif kind == 'harbor_robot_account':
            attributes['id'] = '/robots/' + str(number)
        elif kind == 'harbor_retention_policy':
            attributes.update(id='/retentions/' + str(number), scope='/projects/' + str(projects[key]))
        elif kind == 'harbor_immutable_tag_rule':
            project_id = '/projects/' + str(projects[key])
            attributes.update(id=project_id + '/immutabletagrules/' + str(number), project_id=project_id)
        else:
            raise AssertionError('Unexpected native fixture resource')
        row['change'].update(before=copy.deepcopy(attributes), actions=['no-op'])
    return value

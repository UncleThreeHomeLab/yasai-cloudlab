"""Synthetic policy inputs; no service credentials or cluster access."""
def pod(name='accepted'):
    return {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': 'cloudlab-app-proof'},
            'spec': {'automountServiceAccountToken': False, 'containers': [{
                'name': 'app', 'image': 'example.invalid/public/app@sha256:' + 'a' * 64,
                'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'},
                              'limits': {'cpu': '100m', 'memory': '64Mi'}}}]}}

"""Prove the health identity cannot read credentials, inspect pods or create workloads."""
import importlib.util
import json
import os
import ssl
import urllib.error
import urllib.request

specification = importlib.util.spec_from_file_location('health', '/usr/local/libexec/cloudlab-ci-health.py')
health = importlib.util.module_from_spec(specification)
specification.loader.exec_module(health)
assert health.check()
token = (health.FILES / 'token').read_text().strip()
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), health.NoRedirect(),
    urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(health.FILES / 'ca.crt'))))
namespace = os.environ['POD_NAMESPACE']
for method, path, body in (
        ('GET', '/api/v1/namespaces/' + namespace + '/secrets?limit=1', None),
        ('GET', '/api/v1/namespaces/' + namespace + '/pods?limit=1', None),
        ('POST', '/api/v1/namespaces/' + namespace + '/pods?dryRun=All',
         {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'must-not-create'},
          'spec': {'containers': [{'name': 'denied', 'image': 'example.invalid/denied@sha256:' + 'a' * 64}]}})):
    request = urllib.request.Request(health.SERVER + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    try:
        with opener.open(request, timeout=5):
            raise RuntimeError('Health identity exceeded its read-only scope')
    except urllib.error.HTTPError as error:
        assert error.code == 403
print('CLOUDLAB_CI_API_DENIAL_OK')

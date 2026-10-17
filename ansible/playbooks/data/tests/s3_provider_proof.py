"""Test native AWS bucket calls against the exact disposable SeaweedFS tuple."""
import json
import os
from pathlib import Path
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from provider_proof import WORK, tofu, plan

ENDPOINT = 'http://seaweed:8333'


def request(method, bucket):
    with urllib.request.urlopen(urllib.request.Request(ENDPOINT + '/' + bucket, method=method), timeout=10) as response:
        return response.status


def main():
    os.umask(0o077)
    deadline = time.monotonic() + 120
    while True:
        try:
            request('PUT', 'provider-fixture')
            request('PUT', 'unrelated-fixture')
            break
        except (OSError, urllib.error.URLError):
            if time.monotonic() > deadline:
                raise RuntimeError('Disposable SeaweedFS did not become ready') from None
            time.sleep(2)
    configuration = {'provider': {'aws': {'region': 'us-east-1', 'access_key': 'fixture-only',
                     'secret_key': 'fixture-only', 'skip_credentials_validation': True,
                     'skip_requesting_account_id': True, 'skip_metadata_api_check': True,
                     'skip_region_validation': True, 's3_use_path_style': True,
                     'endpoints': {'s3': ENDPOINT}}},
                     'resource': {'aws_s3_bucket': {'fixture': {'bucket': 'provider-fixture', 'force_destroy': False}}}}
    (WORK / 'main.tf.json').write_text(json.dumps(configuration))
    tofu('validate')
    tofu('import', '-input=false', 'aws_s3_bucket.fixture', 'provider-fixture')
    repeat = plan()
    if repeat:
        raise RuntimeError('SeaweedFS bucket import produced unintended native changes')
    # Losing a bucket must be detected, then repaired without unrelated deletion.
    request('DELETE', 'provider-fixture')
    if plan().get('aws_s3_bucket.fixture') != ['create']:
        raise RuntimeError('Native provider did not detect missing SeaweedFS bucket')
    tofu('apply', '-input=false', '-auto-approve', 'check.tfplan')
    request('HEAD', 'provider-fixture')
    if plan():
        raise RuntimeError('Native SeaweedFS bucket repeat did not converge')
    tofu('destroy', '-input=false', '-auto-approve')
    try:
        request('HEAD', 'provider-fixture')
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
    else:
        raise RuntimeError('Native provider did not delete its empty fixture bucket')
    request('HEAD', 'unrelated-fixture')
    print(json.dumps({'opentofu': '1.13.1', 'provider': 'hashicorp/aws@6.68.0',
                      'api': 'SeaweedFS 4.48 S3', 'bucket_import_supported_in_fixture': True,
                      'repeat_empty': True, 'missing_bucket_repaired': True, 'scoped_empty_bucket_delete': True,
                      'unrelated_bucket_preserved': True, 'iam_tls_rotation_restore_parity_proven': False,
                      'scope': 'isolated anonymous HTTP; no generic S3 compatibility or application-object claim'}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError) else
                         'Disposable S3 provider check failed; private diagnostics withheld') from None
    finally:
        for name in ('main.tf.json', 'check.tfplan', 'terraform.tfstate', 'terraform.tfstate.backup'):
            (WORK / name).unlink(missing_ok=True)

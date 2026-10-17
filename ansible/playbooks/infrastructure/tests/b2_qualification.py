"""Qualify only disposable objects in the separately authorized B2 state bucket."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from dotenv import dotenv_values

from playbooks.secrets.files.vault import fields
from automation.data.s3 import NS, S3, S3Error


def endpoint(values):
    url = values['ENDPOINT']
    if re.fullmatch(r's3\.[a-z0-9-]+\.backblazeb2\.com/?', url):
        url = 'https://' + url
    if not re.fullmatch(r'https://s3\.[a-z0-9-]+\.backblazeb2\.com/?', url):
        raise ValueError('Qualification requires an official B2 HTTPS endpoint')
    if not re.fullmatch(r'[a-zA-Z0-9-]{6,63}', values['BUCKET']):
        raise ValueError('Invalid qualification bucket name')
    return url.rstrip('/')


def headers(response):
    return {key.lower(): value for key, value in response['headers'].items()}


def native_lock(values, url, key):
    """Use the pinned CLI; fail before any provider operation or state write."""
    with tempfile.TemporaryDirectory(prefix='b2-qualification-') as directory:
        root = Path(directory)
        (root / 'main.tf.json').write_text(json.dumps({
            'terraform': {'required_version': '= 1.13.1', 'backend': {'s3': {
                'bucket': values['BUCKET'], 'key': key, 'region': url.split('.')[1],
                'endpoints': {'s3': url}, 'use_lockfile': True, 'use_path_style': True,
                'skip_credentials_validation': True, 'skip_region_validation': True,
                'skip_requesting_account_id': True, 'skip_metadata_api_check': True,
                'skip_s3_checksum': True,
            }}},
            'resource': {'terraform_data': {'disposable': {'input': 'synthetic'}}},
        }))
        environment = {name: os.environ[name] for name in ('PATH', 'HOME') if name in os.environ}
        environment.update(AWS_ACCESS_KEY_ID=values['KEY_ID'], AWS_SECRET_ACCESS_KEY=values['APPLICATION_KEY'],
                           AWS_EC2_METADATA_DISABLED='true', TF_IN_AUTOMATION='true')
        initialized = subprocess.run(['tofu', 'init', '-input=false', '-no-color'], cwd=root,
                                     env=environment, capture_output=True, timeout=120)
        if initialized.returncode:
            return {'native_init': False, 'native_lock_rejected_501': False}
        planned = subprocess.run(['tofu', 'plan', '-input=false', '-no-color', '-lock-timeout=0s'],
                                 cwd=root, env=environment, capture_output=True, timeout=120)
        diagnostics = planned.stdout + planned.stderr
        return {'native_init': True, 'native_lock_rejected_501':
                planned.returncode != 0 and b'Error acquiring the state lock' in diagnostics and b'501' in diagnostics}


def qualify(values, client=S3):
    url = endpoint(values)
    def connection():
        return client(url, values['KEY_ID'], values['APPLICATION_KEY'], url.split('.')[1])
    api = connection()
    prefix = 'qualification/' + secrets.token_hex(16) + '/'
    lock, state = prefix + 'state.tflock', prefix + 'state-sample'
    results = {'production_mutations': 0, 'scope': 'qualification/',
               'conditional_create': False, 'cross_client_lock': False,
               'bucket_encryption': False, 'version_retrieval': False, 'cleanup': False}
    try:
        first = api.request('PUT', values['BUCKET'], lock, data=b'first')
        results['bucket_encryption'] = headers(first).get('x-amz-server-side-encryption') == 'AES256'
        try:
            connection().request('PUT', values['BUCKET'], lock, data=b'second', headers={'If-None-Match': '*'})
        except S3Error as error:
            if error.status not in (412, 501):
                raise
            results['conditional_put_http_status'] = error.status
            results['conditional_create'] = error.status == 412
        # A separate key tests simultaneous acquisition by two independent clients.
        def acquire(number):
            try:
                connection().request('PUT', values['BUCKET'], prefix + 'race.tflock',
                                     data=str(number).encode(), headers={'If-None-Match': '*'})
                return 'acquired'
            except S3Error as error:
                if error.status == 412:
                    return 'rejected'
                if error.status == 501:
                    return 'unsupported'
                raise
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(acquire, (1, 2)))
        results['cross_client_lock'] = sorted(outcomes) == ['acquired', 'rejected']
        results['lock_acquisitions'] = outcomes.count('acquired')
        results['lock_unsupported_responses'] = outcomes.count('unsupported')
        saved = api.request('PUT', values['BUCKET'], state, data=b'synthetic-generation-1')
        version = headers(saved).get('x-amz-version-id')
        if not version:
            raise RuntimeError('B2 upload returned no version identity')
        api.request('PUT', values['BUCKET'], state, data=b'synthetic-generation-2')
        original = connection().request('GET', values['BUCKET'], state, query={'versionId': version})
        current = connection().request('GET', values['BUCKET'], state)
        results['version_retrieval'] = (original['data'] == b'synthetic-generation-1' and
                                        current['data'] == b'synthetic-generation-2')
        if not results['conditional_create']:
            results.update(native_lock(values, url, prefix + 'native.tfstate'))
    finally:
        # Delete only this run's exact versions. Never list or delete backup prefixes.
        document = ET.fromstring(api.request('GET', values['BUCKET'],
                                            query={'versions': '', 'prefix': prefix})['data'])
        if document.findtext('s:IsTruncated', namespaces=NS) == 'true':
            raise RuntimeError('Qualification cleanup listing truncated; retain objects for inspection')
        for kind in ('Version', 'DeleteMarker'):
            for row in document.findall('s:' + kind, NS):
                key = row.findtext('s:Key', namespaces=NS)
                version = row.findtext('s:VersionId', namespaces=NS)
                if key not in (lock, state, prefix + 'race.tflock', prefix + 'native.tfstate',
                               prefix + 'native.tfstate.tflock') or not version:
                    raise RuntimeError('Qualification cleanup escaped its exact disposable scope')
                api.request('DELETE', values['BUCKET'], key, query={'versionId': version})
        remaining = ET.fromstring(api.request('GET', values['BUCKET'],
                                             query={'versions': '', 'prefix': prefix})['data'])
        results['cleanup'] = (not remaining.findall('s:Version', NS) and
                              not remaining.findall('s:DeleteMarker', NS) and
                              remaining.findtext('s:IsTruncated', namespaces=NS) != 'true')
    results['eligible_for_native_locking'] = results['conditional_create'] and results['cross_client_lock']
    return results


def main():
    environment = dotenv_values('/workspace/.env', interpolate=False)
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = environment.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    values = fields('b2-infra-qualification', ('KEY_ID', 'APPLICATION_KEY', 'BUCKET', 'ENDPOINT', 'REGION'))
    result = qualify(values)
    # The receipt contains booleans only, not private locations, keys or version IDs.
    target = Path('/recovery/infra')
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    (target / 'b2-qualification.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if all(result[name] for name in ('eligible_for_native_locking', 'bucket_encryption', 'version_retrieval', 'cleanup')) else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError, OSError):
        raise SystemExit('B2 qualification failed; private diagnostics withheld. No production handoff.') from None

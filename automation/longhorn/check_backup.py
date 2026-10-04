"""Prove S3 list/write/read/delete access with a unique disposable object.

No credentials, bucket names, URLs, response bodies or diagnostic dumps are logged.
Reads the ESO-synchronized Secret from stdin; uses only the Python standard library.
"""

import datetime
import hashlib
import hmac
import os
import json
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request
import uuid

import sys
from monthly_window import require_window


def check(values):
    def setting(name):
        value = values.get(name)
        if not value:
            raise ValueError('Missing synchronized backup field: ' + name)
        return value

    bucket, region = setting('BUCKET'), setting('REGION')
    endpoint = urllib.parse.urlsplit(setting('AWS_ENDPOINTS'))
    access, secret = setting('AWS_ACCESS_KEY_ID'), setting('AWS_SECRET_ACCESS_KEY')
    if endpoint.scheme != 'https' or not endpoint.hostname or endpoint.path not in ('', '/') or endpoint.query or endpoint.username:
        raise ValueError('Backup endpoint must be an HTTPS S3 endpoint without bucket/path or credentials')
    host = endpoint.netloc

    def request(method, key='', query=None, content=b''):
        require_window()
        now = datetime.datetime.now(datetime.timezone.utc)
        stamp, day = now.strftime('%Y%m%dT%H%M%SZ'), now.strftime('%Y%m%d')
        path = '/' + urllib.parse.quote(bucket, safe='') + '/' + urllib.parse.quote(key, safe='/~')
        query_string = urllib.parse.urlencode(sorted((query or {}).items()), quote_via=urllib.parse.quote)
        payload_hash = hashlib.sha256(content).hexdigest()
        headers = {'host': host, 'x-amz-content-sha256': payload_hash, 'x-amz-date': stamp}
        signed = ';'.join(sorted(headers))
        canonical_headers = ''.join(k + ':' + headers[k] + '\n' for k in sorted(headers))
        canonical = '\n'.join((method, path, query_string, canonical_headers, signed, payload_hash))
        scope = day + '/' + region + '/s3/aws4_request'
        to_sign = 'AWS4-HMAC-SHA256\n' + stamp + '\n' + scope + '\n' + hashlib.sha256(canonical.encode()).hexdigest()
        signing_key = ('AWS4' + secret).encode()
        for part in (day, region, 's3', 'aws4_request'):
            signing_key = hmac.new(signing_key, part.encode(), hashlib.sha256).digest()
        signature = hmac.new(signing_key, to_sign.encode(), hashlib.sha256).hexdigest()
        headers['Authorization'] = 'AWS4-HMAC-SHA256 Credential=' + access + '/' + scope + ', SignedHeaders=' + signed + ', Signature=' + signature
        url = 'https://' + host + path + ('?' + query_string if query_string else '')
        try:
            with urllib.request.urlopen(urllib.request.Request(url, data=content if method == 'PUT' else None,
                                                                headers=headers, method=method), timeout=30) as result:
                return result.read()
        except urllib.error.HTTPError as error:
            raise RuntimeError('Backup access check ' + method + ' failed with HTTP ' + str(error.code)) from None
        except urllib.error.URLError:
            raise RuntimeError('Backup endpoint connection failed') from None

    policy = json.loads(Path(__file__).with_name('backup-policy.json').read_text())
    key = policy['prefix'] + '.access-check-' + uuid.uuid4().hex
    content = os.urandom(64)
    request('GET', query={'list-type': '2', 'prefix': key, 'max-keys': '1'})
    try:
        request('PUT', key, content=content)
        if request('GET', key) != content:
            raise RuntimeError('Backup object content mismatch')
    finally:
        request('DELETE', key)
    print('B2 access verified: list, write, read and delete. Disposable object removed.', flush=True)


if __name__ == '__main__':
    try:
        check(json.load(sys.stdin))
    except (ValueError, RuntimeError) as error:
        raise SystemExit(str(error)) from None

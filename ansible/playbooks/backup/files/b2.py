"""Monthly, prefix-scoped S3 cleanup of B2 versions and unfinished uploads."""
from datetime import datetime, timezone
import hashlib
import hmac
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from repository import require_window

NS = {'s': 'http://s3.amazonaws.com/doc/2006-03-01/'}


class S3:
    def __init__(self, values):
        self.values = values
        self.prefix = values['PREFIX']

    def request(self, method, key='', query=None, data=b''):
        # Even cleanup reads are batched into the same monthly workflow.
        require_window(reserve=60)
        if method not in ('GET', 'DELETE') or (key and not key.startswith(self.prefix)):
            raise RuntimeError('B2 cleanup operation escaped its declared scope')
        values = self.values
        endpoint = urllib.parse.urlsplit(values['AWS_ENDPOINT'])
        now = datetime.now(timezone.utc)
        stamp, day = now.strftime('%Y%m%dT%H%M%SZ'), now.strftime('%Y%m%d')
        path = '/' + urllib.parse.quote(values['BUCKET'], safe='') + '/' + urllib.parse.quote(key, safe='/~')
        query_string = urllib.parse.urlencode(sorted((query or {}).items()), quote_via=urllib.parse.quote)
        headers = {'host': endpoint.netloc, 'x-amz-date': stamp,
                   'x-amz-content-sha256': hashlib.sha256(data).hexdigest()}
        signed = ';'.join(sorted(headers))
        canonical = '\n'.join((method, path, query_string,
            ''.join(k + ':' + headers[k] + '\n' for k in sorted(headers)), signed, headers['x-amz-content-sha256']))
        scope = day + '/' + values['REGION'] + '/s3/aws4_request'
        signature_key = ('AWS4' + values['AWS_SECRET_ACCESS_KEY']).encode()
        for part in (day, values['REGION'], 's3', 'aws4_request'):
            signature_key = hmac.new(signature_key, part.encode(), hashlib.sha256).digest()
        text = 'AWS4-HMAC-SHA256\n' + stamp + '\n' + scope + '\n' + hashlib.sha256(canonical.encode()).hexdigest()
        headers['Authorization'] = ('AWS4-HMAC-SHA256 Credential=' + values['AWS_ACCESS_KEY_ID'] + '/' + scope
            + ', SignedHeaders=' + signed + ', Signature=' + hmac.new(signature_key, text.encode(), hashlib.sha256).hexdigest())
        request = urllib.request.Request(values['AWS_ENDPOINT'].rstrip('/') + path + '?' + query_string,
            headers=headers, data=data if method == 'PUT' else None, method=method)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            raise RuntimeError('Monthly B2 operation failed: HTTP ' + str(error.code)) from None
        except urllib.error.URLError:
            raise RuntimeError('Monthly B2 endpoint unavailable') from None

    def versions(self):
        query = {'versions': '', 'prefix': self.prefix}
        result = []
        while True:
            root = ET.fromstring(self.request('GET', query=query))
            for kind in ('Version', 'DeleteMarker'):
                for row in root.findall('s:' + kind, NS):
                    key = row.findtext('s:Key', namespaces=NS)
                    if not key or not key.startswith(self.prefix):
                        raise RuntimeError('B2 listing escaped the recovery prefix')
                    result.append({'key': key, 'version': row.findtext('s:VersionId', namespaces=NS),
                        'latest': row.findtext('s:IsLatest', namespaces=NS) == 'true', 'kind': kind,
                        'size': int(row.findtext('s:Size', default='0', namespaces=NS))})
            if root.findtext('s:IsTruncated', namespaces=NS) != 'true':
                return result
            query['key-marker'] = root.findtext('s:NextKeyMarker', namespaces=NS)
            query['version-id-marker'] = root.findtext('s:NextVersionIdMarker', namespaces=NS)

    def cleanup(self):
        versions = self.versions()
        # Delete old data before markers. An interrupted cleanup must not reveal it.
        for row in versions:
            if row['kind'] == 'Version' and not row['latest']:
                self.request('DELETE', row['key'], {'versionId': row['version']})
        for row in versions:
            if row['kind'] == 'DeleteMarker':
                self.request('DELETE', row['key'], {'versionId': row['version']})
        query = {'uploads': '', 'prefix': self.prefix}
        while True:
            root = ET.fromstring(self.request('GET', query=query))
            for row in root.findall('s:Upload', NS):
                key = row.findtext('s:Key', namespaces=NS)
                if not key or not key.startswith(self.prefix):
                    raise RuntimeError('Multipart listing escaped the recovery prefix')
                self.request('DELETE', key, {'uploadId': row.findtext('s:UploadId', namespaces=NS)})
            if root.findtext('s:IsTruncated', namespaces=NS) != 'true':
                break
            query['key-marker'] = root.findtext('s:NextKeyMarker', namespaces=NS)
            query['upload-id-marker'] = root.findtext('s:NextUploadIdMarker', namespaces=NS)
        remaining = self.versions()
        if any(r['kind'] != 'Version' or not r['latest'] for r in remaining):
            raise RuntimeError('Hidden B2 recovery history remains after cleanup')
        return sum(r['size'] for r in remaining)

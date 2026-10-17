"""Bounded native B2 metadata reads and explicit version deletion."""
import base64
import json
import urllib.error
import urllib.request


def request(url, token, body=None):
    req = urllib.request.Request(url, headers={'Authorization': token, 'Content-Type': 'application/json'},
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError('B2 operation failed: HTTP ' + str(error.code)) from None
    except urllib.error.URLError:
        raise RuntimeError('B2 endpoint unavailable') from None


class NativeAPI:
    def __init__(self, values):
        basic = base64.b64encode((values['AWS_ACCESS_KEY_ID'] + ':' + values['AWS_SECRET_ACCESS_KEY']).encode()).decode()
        self.auth = request('https://api.backblazeb2.com/b2api/v4/b2_authorize_account', 'Basic ' + basic)
        self.storage = self.auth['apiInfo']['storageApi']
        buckets = self.read('b2_list_buckets', {'accountId': self.auth['accountId'], 'bucketName': values['BUCKET']})['buckets']
        if len(buckets) != 1:
            raise RuntimeError('Expected exactly one configured backup bucket')
        self.bucket = buckets[0]

    def read(self, operation, body):
        if operation not in ('b2_list_buckets', 'b2_list_file_versions', 'b2_list_unfinished_large_files'):
            raise RuntimeError('Read path permits only B2 metadata/list operations')
        return request(self.storage['apiUrl'] + '/b2api/v4/' + operation, self.auth['authorizationToken'], body)

    def versions(self, prefix):
        body = {'bucketId': self.bucket['bucketId'], 'prefix': prefix, 'maxFileCount': 1000}
        files = []
        cursors = set()
        for _ in range(100):
            page = self.read('b2_list_file_versions', body)
            if any(not row['fileName'].startswith(prefix) for row in page['files']):
                raise RuntimeError('B2 listing escaped the requested prefix')
            files.extend(page['files'])
            if not page.get('nextFileName'):
                return files
            cursor = (page['nextFileName'], page['nextFileId'])
            if cursor in cursors:
                raise RuntimeError('B2 pagination did not advance')
            cursors.add(cursor)
            body.update(startFileName=cursor[0], startFileId=cursor[1])
        raise RuntimeError('B2 inventory exceeded the bounded review size')

    def delete_version(self, row, prefix, guard):
        guard(reserve=60)
        if not prefix or not row['fileName'].startswith(prefix) or row['action'] != 'upload':
            raise RuntimeError('Version deletion escaped its declared scope')
        request(self.storage['apiUrl'] + '/b2api/v4/b2_delete_file_version', self.auth['authorizationToken'],
                {'fileName': row['fileName'], 'fileId': row['fileId']})

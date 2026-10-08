"""Bounded private S3 operations with SigV4, verified TLS and no redirects."""
from datetime import datetime, timezone
import hashlib
import hmac
import json
import http.client
import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

NS = {'s': 'http://s3.amazonaws.com/doc/2006-03-01/'}


class S3Error(RuntimeError):
    def __init__(self, status):
        self.status = status
        super().__init__('Private S3 request failed: HTTP ' + str(status))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class S3:
    def __init__(self, endpoint, access, secret, region='us-east-1', address=None, source_address=None):
        parsed = urllib.parse.urlsplit(endpoint)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
                or parsed.path not in ('', '/') or parsed.query or parsed.fragment):
            raise ValueError('S3 requires a verified HTTPS endpoint without path or user info')
        if not access or not secret or not region:
            raise ValueError('Incomplete S3 identity')
        self.endpoint, self.host = endpoint.rstrip('/'), parsed.netloc
        self.access, self.secret, self.region = access, secret, region
        self.opener = urllib.request.build_opener(NoRedirect())
        if source_address is not None and (address is None or not ipaddress.ip_address(source_address).is_private):
            raise ValueError('Restore source address must be private and use a dial override')
        if address is not None:
            # Isolated restore uses a private Service IP while preserving hostname
            # verification and SNI. Never disable certificate verification.
            if not ipaddress.ip_address(address).is_private:
                raise ValueError('Restore dial override must be a private IP')
            class Connection(http.client.HTTPSConnection):
                def connect(self):
                    raw = socket.create_connection((address, self.port), self.timeout,
                                                   source_address=(source_address, 0) if source_address else None)
                    self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
            class Handler(urllib.request.HTTPSHandler):
                def https_open(self, request):
                    return self.do_open(Connection, request, context=self._context)
            self.opener = urllib.request.build_opener(NoRedirect(), Handler())
        self.requests = 0
        self.sent_bytes = 0
        self.received_bytes = 0

    def signature(self, method, path, query, headers, stamp, payload_hash):
        headers = {k.lower(): ' '.join(v.strip().split()) for k, v in headers.items()}
        signed = ';'.join(sorted(headers))
        canonical = '\n'.join([method, path, query,
                               ''.join(k + ':' + headers[k] + '\n' for k in sorted(headers)),
                               signed, payload_hash])
        day = stamp[:8]
        scope = day + '/' + self.region + '/s3/aws4_request'
        key = ('AWS4' + self.secret).encode()
        for value in (day, self.region, 's3', 'aws4_request'):
            key = hmac.new(key, value.encode(), hashlib.sha256).digest()
        message = 'AWS4-HMAC-SHA256\n' + stamp + '\n' + scope + '\n' + hashlib.sha256(canonical.encode()).hexdigest()
        signature = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
        return signed, scope, signature

    @staticmethod
    def path(bucket, key=''):
        if not bucket or '/' in bucket:
            raise ValueError('An explicit S3 bucket is required')
        return '/' + urllib.parse.quote(bucket, safe='') + '/' + urllib.parse.quote(key, safe='/~')

    def request(self, method, bucket, key='', query=None, data=b'', headers=None, target=None, limit=16 * 1024**2):
        path = self.path(bucket, key)
        query = urllib.parse.urlencode(sorted((query or {}).items()), quote_via=urllib.parse.quote)
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        headers = {k.lower(): str(v) for k, v in (headers or {}).items()}
        headers.update(host=self.host, **{'x-amz-date': stamp, 'x-amz-content-sha256': hashlib.sha256(data).hexdigest()})
        signed, scope, signature = self.signature(method, path, query, headers, stamp, headers['x-amz-content-sha256'])
        headers['authorization'] = ('AWS4-HMAC-SHA256 Credential=' + self.access + '/' + scope
                                    + ', SignedHeaders=' + signed + ', Signature=' + signature)
        request = urllib.request.Request(self.endpoint + path + ('?' + query if query else ''),
                                         method=method, headers=headers,
                                         data=data if method in ('PUT', 'POST') else None)
        self.requests += 1
        self.sent_bytes += len(data)
        try:
            with self.opener.open(request, timeout=60) as response:
                size, chunks, digest = 0, [], hashlib.sha256()
                while chunk := response.read(1024**2):
                    size += len(chunk)
                    if size > limit:
                        raise RuntimeError('S3 response exceeds the declared byte limit')
                    digest.update(chunk)
                    if target is not None:
                        target.write(chunk)
                    else:
                        chunks.append(chunk)
                self.received_bytes += size
                return {'data': b''.join(chunks), 'headers': dict(response.headers.items()),
                        'bytes': size, 'sha256': digest.hexdigest()}
        except urllib.error.HTTPError as error:
            raise S3Error(error.code) from None
        except (urllib.error.URLError, TimeoutError):
            raise RuntimeError('Private S3 endpoint unavailable or TLS verification failed') from None

    def ensure_bucket(self, bucket):
        try:
            self.request('HEAD', bucket)
            return False
        except S3Error as error:
            if error.status != 404:
                raise
        self.request('PUT', bucket)
        self.request('HEAD', bucket)
        return True

    def objects(self, bucket):
        query = {'list-type': '2'}
        seen = set()
        for _ in range(10000):
            root = ET.fromstring(self.request('GET', bucket, query=query)['data'])
            for row in root.findall('s:Contents', NS):
                key = row.findtext('s:Key', namespaces=NS)
                if key is None or key in seen:
                    raise RuntimeError('S3 returned an ambiguous object listing')
                seen.add(key)
                yield {'key': key, 'size': int(row.findtext('s:Size', namespaces=NS))}
            if root.findtext('s:IsTruncated', namespaces=NS) != 'true':
                return
            token = root.findtext('s:NextContinuationToken', namespaces=NS)
            if not token or token == query.get('continuation-token'):
                raise RuntimeError('S3 pagination did not advance')
            query['continuation-token'] = token
        raise RuntimeError('S3 listing exceeds the object count limit')

    def presign(self, method, bucket, key, expires=60):
        if not 1 <= expires <= 300 or method not in ('GET', 'PUT'):
            raise ValueError('Presigned fixture requests are GET/PUT with at most five minutes validity')
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        scope = stamp[:8] + '/' + self.region + '/s3/aws4_request'
        query = {'X-Amz-Algorithm': 'AWS4-HMAC-SHA256', 'X-Amz-Credential': self.access + '/' + scope,
                 'X-Amz-Date': stamp, 'X-Amz-Expires': str(expires), 'X-Amz-SignedHeaders': 'host'}
        encoded = urllib.parse.urlencode(sorted(query.items()), quote_via=urllib.parse.quote)
        _, _, signature = self.signature(method, self.path(bucket, key), encoded,
                                         {'host': self.host}, stamp, 'UNSIGNED-PAYLOAD')
        return self.endpoint + self.path(bucket, key) + '?' + encoded + '&X-Amz-Signature=' + signature

    def upload(self, bucket, key, path, headers=None):
        if path.stat().st_size <= 8 * 1024**2:
            return self.request('PUT', bucket, key, data=path.read_bytes(), headers=headers)
        response = self.request('POST', bucket, key, query={'uploads': ''}, headers=headers)
        upload = ET.fromstring(response['data']).findtext('s:UploadId', namespaces=NS)
        if not upload:
            raise RuntimeError('S3 did not return a multipart upload identity')
        parts = ET.Element('CompleteMultipartUpload')
        try:
            with path.open('rb') as source:
                number = 0
                while chunk := source.read(8 * 1024**2):
                    number += 1
                    response = self.request('PUT', bucket, key, query={'uploadId': upload, 'partNumber': str(number)}, data=chunk)
                    etag = {k.lower(): v for k, v in response['headers'].items()}.get('etag')
                    if not etag:
                        raise RuntimeError('S3 multipart response has no ETag')
                    part = ET.SubElement(parts, 'Part')
                    ET.SubElement(part, 'PartNumber').text = str(number)
                    ET.SubElement(part, 'ETag').text = etag
            result = self.request('POST', bucket, key, query={'uploadId': upload}, data=ET.tostring(parts))
            if ET.fromstring(result['data']).tag.split('}')[-1] != 'CompleteMultipartUploadResult':
                raise RuntimeError('S3 multipart completion returned an embedded error')
            return result
        except Exception:
            self.request('DELETE', bucket, key, query={'uploadId': upload})
            raise

    def counters(self):
        return {'requests': self.requests, 'sent_bytes': self.sent_bytes, 'received_bytes': self.received_bytes}

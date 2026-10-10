"""Small bounded DNS client for independent UDP/TCP and authoritative-answer proof."""
import secrets
import ipaddress
import socket
import struct


def name_end(data, offset):
    for _ in range(128):
        size = data[offset]
        if size & 0xc0 == 0xc0:
            return offset + 2
        offset += 1
        if not size:
            return offset
        if size > 63 or offset + size >= len(data):
            raise ValueError('Invalid DNS response name')
        offset += size
    raise ValueError('Unbounded DNS response name')


def query(address, name, *, port=53, source=None, tcp=False):
    identity = secrets.randbelow(65536)
    labels = name.rstrip('.').encode('ascii').split(b'.')
    if not labels or any(not label or len(label) > 63 for label in labels):
        raise ValueError('Invalid DNS query name')
    request = struct.pack('!6H', identity, 0x100, 1, 0, 0, 0) + b''.join(bytes([len(x)]) + x for x in labels) + b'\0\0\1\0\1'
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as connection:
        connection.settimeout(3)
        if source:
            connection.bind((source, 0))
        connection.connect((address, port))
        if tcp:
            connection.sendall(struct.pack('!H', len(request)) + request)

            def read(count):
                result = b''
                while len(result) < count:
                    chunk = connection.recv(count - len(result))
                    if not chunk:
                        raise ValueError('Truncated DNS stream')
                    result += chunk
                return result
            size = struct.unpack('!H', read(2))[0]
            if size > 4096:
                raise ValueError('Oversized DNS response')
            data = read(size)
        else:
            connection.send(request)
            data = connection.recv(4096)
    received, flags, questions, answers, _, _ = struct.unpack('!6H', data[:12])
    if received != identity or not flags & 0x8000 or flags & 0x200 or questions != 1:
        raise ValueError('Invalid or truncated DNS response')
    offset = name_end(data, 12) + 4
    addresses = []
    for _ in range(answers):
        offset = name_end(data, offset)
        kind, family, _, size = struct.unpack('!HHIH', data[offset:offset + 10])
        offset += 10
        if kind == 1 and family == 1 and size == 4:
            addresses.append(socket.inet_ntoa(data[offset:offset + 4]))
        offset += size
    return {'rcode': flags & 15, 'authoritative': bool(flags & 0x400), 'addresses': addresses}


def private_answer(address, name, expected, **kwargs):
    result = query(address, name, **kwargs)
    if result != {'rcode': 0, 'authoritative': True, 'addresses': [expected]}:
        raise RuntimeError('Private DNS answer did not match the selected view')


def public_address(name):
    """Resolve outside split DNS so a private peer cannot satisfy public proof."""
    for resolver in ('1.1.1.1', '8.8.8.8'):
        try:
            result = query(resolver, name, tcp=True)
        except (OSError, ValueError):
            continue
        if result['rcode'] == 0 and result['addresses'] and all(
                ipaddress.ip_address(value).is_global for value in result['addresses']):
            return result['addresses'][0]
        raise RuntimeError('Public identity DNS answer is not a public peer')
    raise RuntimeError('Independent public identity DNS lookup failed')


def absent_answer(address, name, **kwargs):
    result = query(address, name, **kwargs)
    if result['rcode'] != 3 or not result['authoritative'] or result['addresses']:
        raise RuntimeError('Unknown private name did not fail authoritatively')

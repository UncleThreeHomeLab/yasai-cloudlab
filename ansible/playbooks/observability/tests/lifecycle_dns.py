"""Bounded DNS observations on the fixture's shared Docker Linux monotonic clock."""
import ast
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
import time
import urllib.error


ZONE = 'example.test'
LOGIN_HOST = 'login.' + ZONE
GRAFANA_HOST = 'grafana.internal.' + ZONE
KIALI_HOST = 'kiali.internal.' + ZONE
ISSUER = 'https://' + LOGIN_HOST + '/realms/platform'


UID = re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}')
HEX = re.compile(r'[a-f0-9]{64}')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def wire_source():
    source = Path('/workspace/verification/integration/workload_egress.py').read_text()
    nodes = [node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef)
             and node.name in {'question', 'dns_name', 'dns_response'}]
    if len(nodes) != 3 or {node.name for node in nodes} != {'question', 'dns_name', 'dns_response'}:
        raise RuntimeError('Strict DNS definitions are unavailable')
    return ('import ipaddress,re,struct\n'
            'def fail(message): raise ValueError("invalid-dns")\n'
            + '\n\n'.join(ast.get_source_segment(source, node) for node in nodes) + '\n')


def diagnostic_config(control, resolver, cluster, issuer, applied_at):
    now = time.monotonic()
    if (control not in ('ordinary', 'ambient') or type(applied_at) not in (int, float)
            or not math.isfinite(applied_at) or not 0 <= applied_at <= now or now - applied_at > 3600):
        raise RuntimeError('Invalid DNS diagnostic scope')
    for address in (resolver, cluster, issuer):
        ipaddress.IPv4Address(address)
    return {'control': control, 'resolver': resolver, 'cluster': cluster, 'issuer': issuer,
            'issuerHost': LOGIN_HOST, 'appliedAt': applied_at}


def diagnostic_code(control, resolver, cluster, issuer, applied_at, *, nonce):
    config = diagnostic_config(control, resolver, cluster, issuer, applied_at)
    if not HEX.fullmatch(nonce): raise RuntimeError('Invalid DNS operation nonce')
    return (wire_source() + 'config=' + repr(config) + '\noperation_nonce=' + repr(nonce) + '\n'
            + DNS_CODE + PROTOCOL_CODE)


def matrix_ready(rows):
    expected = [('resolver', 'metadata')] + [(name, transport) for name in ('cluster-a', 'issuer-a')
                                           for transport in ('udp', 'tcp', 'system')]
    if type(rows) is not list or len(rows) != len(expected):
        raise RuntimeError('DNS diagnostic matrix is incomplete')
    for row, (query, transport) in zip(rows, expected):
        if (type(row) is not dict or set(row) != {'control', 'query', 'transport', 'expectedAnswer', 'rcode', 'errno', 'elapsedCMApply'}
                or row['control'] not in ('ordinary', 'ambient') or row['query'] != query or row['transport'] != transport
                or type(row['expectedAnswer']) is not bool or row['rcode'] not in ('NOERROR', 'SERVFAIL', 'invalid', 'not-applicable')
                or row['errno'] not in ('none', 'timeout', 'refused', 'unreachable', 'dns', 'invalid', 'other')
                or type(row['elapsedCMApply']) is not int or not 0 <= row['elapsedCMApply'] <= 3840):
            raise RuntimeError('DNS diagnostic schema refused')
    return all(row['expectedAnswer'] is True and row['errno'] == 'none'
               and row['rcode'] == ('NOERROR' if row['transport'] in ('udp', 'tcp') else 'not-applicable') for row in rows)


def log_records(raw, *, pod_uid, job_uid, nonce, config_hash, control):
    if type(raw) is not bytes or len(raw) > 8192 or raw and not raw.endswith(b'\n'):
        raise RuntimeError('DNS log frame refused')
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value: raise RuntimeError('DNS log duplicate key')
            value[key] = item
        return value
    try:
        records = [json.loads(line, object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError())) for line in raw.splitlines()]
    except (ValueError, UnicodeError): raise RuntimeError('DNS log JSON refused') from None
    if len(records) > 2: raise RuntimeError('DNS log sequence refused')
    binding = None
    for index, record in enumerate(records):
        fields = {'kind', 'binding'} if index == 0 else {'kind', 'binding', 'dns', 'exitCode', 'resultDigest'}
        if type(record) is not dict or set(record) != fields or record['kind'] != ('waiting' if index == 0 else 'result'):
            raise RuntimeError('DNS log sequence refused')
        current = record['binding']
        if (type(current) is not dict or set(current) != {'podUID', 'jobUID', 'nonce', 'configHash', 'pid'}
                or current['podUID'] != pod_uid or not UID.fullmatch(current['podUID'])
                or current['jobUID'] != job_uid or not UID.fullmatch(current['jobUID'])
                or current['nonce'] != nonce or not HEX.fullmatch(current['nonce'])
                or current['configHash'] != config_hash or not HEX.fullmatch(current['configHash'])
                or type(current['pid']) is not int or current['pid'] != 1
                or binding is not None and current != binding):
            raise RuntimeError('DNS process binding refused')
        binding = current
        if index == 1:
            ready = matrix_ready(record['dns'])
            if (any(row['control'] != control for row in record['dns']) or type(record['exitCode']) is not int
                    or record['exitCode'] != (0 if ready else 1) or type(record['resultDigest']) is not str
                    or not HEX.fullmatch(record['resultDigest']) or record['resultDigest'] != digest({
                        'binding': binding, 'dns': record['dns'], 'exitCode': record['exitCode']})):
                raise RuntimeError('DNS result digest refused')
    return records


def same_execution_source(actual, expected):
    if (any(actual.get(key) not in (None, []) for key in ('initContainers', 'ephemeralContainers'))
            or len(actual.get('containers', [])) != 1 or len(expected.get('containers', [])) != 1
            or any(actual.get(key) != expected[key] for key in
                   ('securityContext', 'serviceAccountName', 'automountServiceAccountToken', 'volumes'))):
        return False
    container, wanted = actual['containers'][0], expected['containers'][0]
    if (any(container.get(key) not in (None, []) for key in ('envFrom', 'args'))
            or container.get('workingDir') not in (None, '')
            or any(container.get(key) not in (None, {}) for key in
                   ('lifecycle', 'livenessProbe', 'readinessProbe', 'startupProbe'))):
        return False
    return all(container.get(key) == wanted.get(key) for key in
               ('name', 'image', 'command', 'env', 'resources', 'securityContext', 'volumeMounts'))


def pod_identity(pod, job_uid, expected_spec, control, *, terminal=False):
    """Enrollment at two running boundaries, never a continuous-watch claim."""
    metadata, spec, status = pod['metadata'], pod['spec'], pod.get('status', {})
    labels, annotations = metadata.get('labels', {}), metadata.get('annotations', {})
    if (not UID.fullmatch(metadata['uid']) or labels.get('batch.kubernetes.io/controller-uid') != job_uid
            or not any(owner.get('uid') == job_uid and owner.get('kind') == 'Job' and owner.get('controller') is True
                       for owner in metadata.get('ownerReferences', []))
            or labels.get('cloudlab.io/lifecycle-probe') != 'true' or 'istio.io/dataplane-mode' in labels
            or any(spec.get(key) for key in ('hostNetwork', 'hostPID', 'hostIPC', 'shareProcessNamespace', 'hostAliases', 'dnsConfig'))
            or spec.get('dnsPolicy') != 'ClusterFirst' or spec.get('serviceAccountName') != 'fixture-issuer-probe'
            or spec.get('automountServiceAccountToken') is not False or not same_execution_source(spec, expected_spec)
            or not terminal and ('ambient.istio.io/dns-capture' in annotations or 'sidecar.istio.io/inject' in annotations)):
        raise RuntimeError('DNS Pod source or ownership refused')
    if not terminal and status.get('phase') == 'Pending':
        if any(item.get('restartCount', 0) or item.get('state', {}).get('terminated') for item in status.get('containerStatuses', [])):
            raise RuntimeError('DNS process exited prematurely')
        return None
    capture = annotations.get('ambient.istio.io/redirection')
    if not terminal and (capture != 'enabled' if control == 'ambient' else 'ambient.istio.io/redirection' in annotations):
        raise RuntimeError('Running DNS Pod enrollment refused')
    containers = status.get('containerStatuses', [])
    if len(containers) != 1: raise RuntimeError('DNS container identity is unavailable')
    container = containers[0]
    state = (container.get('state', {}).get('terminated') or container.get('state', {}).get('running', {})) if terminal else container.get('state', {}).get('running', {})
    if (container.get('name') != 'probe' or type(container.get('restartCount')) is not int or container['restartCount'] != 0
            or not re.fullmatch(r'containerd://[a-f0-9]{64}', container.get('containerID', ''))
            or not state.get('startedAt') or not terminal and (status.get('phase') != 'Running'
                or container.get('ready') is not True or container.get('started') is not True)):
        raise RuntimeError('DNS process exited or changed prematurely')
    return {'podUID': metadata['uid'], 'containerID': container['containerID'], 'startedAt': state['startedAt'],
            'restarts': container['restartCount']}


def read_logs(api, namespace, name, deadline):
    if namespace not in ('external-secrets', 'cloudlab-identity') or not re.fullmatch(r'fixture-[a-z0-9-]{1,100}', name):
        raise RuntimeError('DNS log target refused')
    remaining = deadline - time.monotonic()
    if remaining <= 0: raise RuntimeError('DNS operation deadline exceeded')
    uri = 'https://cluster:6443/api/v1/namespaces/' + namespace + '/pods/' + name + '/log?limitBytes=8192'
    try:
        with api.opener.open(uri, timeout=min(15, remaining)) as response:
            if response.status != 200: raise RuntimeError('DNS log response refused')
            raw = response.read(8193)
    except urllib.error.HTTPError: raise RuntimeError('DNS log response unavailable') from None
    if len(raw) > 8192: raise RuntimeError('DNS log byte bound exceeded')
    return raw


def update_gate(api, path, gate, phase, binding, *, result=None, verified=False):
    current = json.loads(gate['data']['gate.json'])
    if phase not in ('run', 'finish') or current['phase'] != ('hold' if phase == 'run' else 'run'):
        raise RuntimeError('DNS gate transition refused')
    if (current['nonce'] != binding['nonce'] or current['configHash'] != binding['configHash']
            or phase == 'finish' and (current['podUID'] != binding['podUID'] or current['jobUID'] != binding['jobUID']
                or verified is not True or result is None or result['binding'] != binding
                or result['resultDigest'] != digest({key: result[key] for key in ('binding', 'dns', 'exitCode')}))):
        raise RuntimeError('DNS gate proof is incomplete')
    document = {'phase': phase, 'nonce': binding['nonce'], 'configHash': binding['configHash'],
        'podUID': binding['podUID'], 'jobUID': binding['jobUID'],
        'resultDigest': result['resultDigest'] if phase == 'finish' else ''}
    data = {'gate.json': json.dumps(document, sort_keys=True, separators=(',', ':'))}
    value = api.request(path, 'PATCH', [
        {'op': 'test', 'path': '/metadata/uid', 'value': gate['metadata']['uid']},
        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': gate['metadata']['resourceVersion']},
        {'op': 'test', 'path': '/data', 'value': gate['data']},
        {'op': 'replace', 'path': '/data', 'value': data}], content_type='application/json-patch+json')
    if value['metadata']['uid'] != gate['metadata']['uid'] or value['data'] != data:
        raise RuntimeError('DNS gate identity changed')
    return value


DNS_CODE = '''import errno,json,math,signal,socket,time
from pathlib import Path

def normalized_error(error):
 if isinstance(error,TimeoutError): return "timeout"
 if isinstance(error,socket.gaierror): return "dns"
 if isinstance(error,OSError):
  if error.errno==errno.ECONNREFUSED: return "refused"
  if error.errno in (errno.EHOSTUNREACH,errno.ENETUNREACH): return "unreachable"
  return "other"
 return "invalid" if isinstance(error,(ValueError,struct.error,RecursionError)) else "other"

def receive_exact(connection,length,deadline):
 data=b""
 while len(data)<length:
  remaining=deadline-time.monotonic()
  if remaining<=0: raise TimeoutError()
  connection.settimeout(remaining)
  part=connection.recv(length-len(data))
  if not part: raise ValueError()
  data+=part
 return data

def exchange(query,tcp):
 deadline=time.monotonic()+3
 with socket.socket(socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as connection:
  connection.settimeout(3)
  connection.connect((config["resolver"],53))
  remaining=deadline-time.monotonic()
  if remaining<=0: raise TimeoutError()
  connection.settimeout(remaining)
  if tcp:
   connection.sendall(struct.pack("!H",len(query))+query)
   header=receive_exact(connection,2,deadline)
   length=int.from_bytes(header,"big")
   if not 12<=length<=4096: raise ValueError()
   return header+receive_exact(connection,length,deadline)
  connection.send(query)
  remaining=deadline-time.monotonic()
  if remaining<=0: raise TimeoutError()
  connection.settimeout(remaining)
  packet=connection.recv(4097)
  if not 12<=len(packet)<=4096: raise ValueError()
  return struct.pack("!H",len(packet))+packet

def validated_answer(raw,query,expected):
 result=dns_response(raw,query,expected)
 if result=="success" and int.from_bytes(raw[8:10],"big")!=1: raise ValueError()
 return result

def alarm_timeout(signum,frame): raise TimeoutError()

def collect():
 last=time.monotonic()
 if not math.isfinite(config["appliedAt"]) or not 0<=config["appliedAt"]<=last: raise SystemExit(2)
 rows=[]
 def row(query,transport,answer,rcode="not-applicable",error="none"):
  nonlocal last
  now=time.monotonic()
  if now<last or now<config["appliedAt"] or now-config["appliedAt"]>3840: raise SystemExit(2)
  last=now
  rows.append({"control":config["control"],"query":query,"transport":transport,"expectedAnswer":answer,
   "rcode":rcode,"errno":error,"elapsedCMApply":int(now-config["appliedAt"])})
 try:
  with open("/etc/resolv.conf") as stream: resolver_text=stream.read(4097)
  if len(resolver_text)>4096: raise ValueError()
  nameservers=[line.split()[1] for line in resolver_text.splitlines() if line.split() and line.split()[0]=="nameserver"]
  row("resolver","metadata",nameservers==[config["resolver"]])
 except Exception as error: row("resolver","metadata",False,error=normalized_error(error))
 for index,(identifier,name,expected) in enumerate((
   ("cluster-a","kubernetes.default.svc.cluster.local.",config["cluster"]),
   ("issuer-a",config["issuerHost"]+".",config["issuer"]))):
  for tcp in (False,True):
   query=question(name,transaction=0x6a31+index*2+int(tcp))
   try:
    result=validated_answer(exchange(query,tcp),query,expected)
    row(identifier,"tcp" if tcp else "udp",result=="success","NOERROR" if result=="success" else "SERVFAIL")
   except Exception as error: row(identifier,"tcp" if tcp else "udp",False,"invalid",normalized_error(error))
  previous=signal.signal(signal.SIGALRM,alarm_timeout)
  try:
   signal.alarm(3)
   system_name=config["issuerHost"] if identifier=="issuer-a" else name
   addresses={item[4][0] for item in socket.getaddrinfo(system_name,None,socket.AF_INET,socket.SOCK_STREAM)}
   row(identifier,"system",addresses=={expected})
  except Exception as error: row(identifier,"system",False,error=normalized_error(error))
  finally:
   signal.alarm(0)
   signal.signal(signal.SIGALRM,previous)
 return rows

'''


PROTOCOL_CODE = '''import hashlib,os

def canonical_digest(value):
 return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":")).encode()).hexdigest()

def strict_gate():
 def pairs(items):
  value={}
  for key,item in items:
   if key in value: raise ValueError()
   value[key]=item
  return value
 with open("/fixture-gate/gate.json") as stream: raw=stream.read(4097)
 if len(raw)>4096: raise ValueError()
 document=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
 if (type(document) is not dict or set(document)!={"phase","nonce","configHash","podUID","jobUID","resultDigest"}
     or any(type(value) is not str for value in document.values())): raise ValueError()
 return document

def held_lifecycle():
 last=time.monotonic()
 deadline=last+240
 def clock():
  nonlocal last
  now=time.monotonic()
  if now<last: raise ValueError()
  last=now
  return now
 if not math.isfinite(config["appliedAt"]) or not 0<=config["appliedAt"]<=clock(): raise ValueError()
 pod_uid=os.environ["FIXTURE_POD_UID"]
 job_uid=os.environ["FIXTURE_JOB_UID"]
 if any(not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}",value) for value in (pod_uid,job_uid)):
  raise ValueError()
 binding={"podUID":pod_uid,"jobUID":job_uid,"nonce":operation_nonce,"configHash":canonical_digest(config),"pid":os.getpid()}
 initial={"phase":"hold","nonce":operation_nonce,"configHash":binding["configHash"],"podUID":"","jobUID":"","resultDigest":""}
 if strict_gate()!=initial: raise ValueError()
 print(json.dumps({"kind":"waiting","binding":binding},sort_keys=True),flush=True)
 def pause():
  remaining=deadline-clock()
  if remaining<=0: raise TimeoutError()
  time.sleep(min(0.2,remaining))
 run={**initial,"phase":"run","podUID":pod_uid,"jobUID":job_uid}
 while True:
  document=strict_gate()
  if document==run: break
  if document!=initial: raise ValueError()
  pause()
 if clock()>=deadline: raise TimeoutError()
 rows=collect()
 result={"binding":binding,"dns":rows,"exitCode":0 if all(row["expectedAnswer"] is True for row in rows) else 1}
 result["resultDigest"]=canonical_digest(result)
 print(json.dumps({"kind":"result",**result},sort_keys=True),flush=True)
 finish={**run,"phase":"finish","resultDigest":result["resultDigest"]}
 while True:
  document=strict_gate()
  if document==finish: break
  if document!=run: raise ValueError()
  pause()
 if clock()>=deadline: raise TimeoutError()
 raise SystemExit(result["exitCode"])

if __name__=="__main__":
 try: held_lifecycle()
 except Exception: raise SystemExit(2)
'''

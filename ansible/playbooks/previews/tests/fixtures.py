"""Credential-free immutable preview examples."""
import copy
import json
import base64
from playbooks.previews.files.contract import IMAGE, SOURCE_PATH, canonical, digest, names


def approval(instance='a' * 32):
    definition = {'profile': 'synthetic', 'message': 'synthetic preview'}
    return {'instance': instance, 'repository': 'example/platform', 'repositoryId': 123, 'pullRequest': 7,
        'sourceSha': 'b' * 40, 'sourcePath': SOURCE_PATH, 'sourceDigest': digest(canonical(definition)),
        'definition': definition, 'image': IMAGE, 'platformRevision': 'c' * 40,
        'createdAt': 1000, 'expiresAt': 2000}


def catalog(rows=None):
    rows = [approval()] if rows is None else rows
    return {'hostname': 'preview.internal.example.invalid', 'issuer': 'https://login.example.invalid/realms/applications',
            'privateDiscovery': False, 'approvals': rows, 'artifacts': {},
            'ownership': {names(row)['namespace']: row['instance'] + ':' + digest(canonical(row)) for row in rows}}


def pull(row=None):
    row = row or approval()
    repo = {'id': row['repositoryId'], 'full_name': row['repository'], 'fork': False, 'private': False}
    return {'number': row['pullRequest'], 'state': 'open', 'draft': False,
            'head': {'sha': row['sourceSha'], 'repo': copy.deepcopy(repo)}, 'base': {'repo': repo}}


def source_responses(row, mode='100644'):
    raw = canonical(row['definition'])
    root, directory, blob = ('1' * 40, '2' * 40, '3' * 40)
    prefix = 'repos/' + row['repository']
    return {
        prefix + '/git/commits/' + row['sourceSha']: {'sha': row['sourceSha'], 'tree': {'sha': root}},
        prefix + '/git/trees/' + root: {'sha': root, 'truncated': False,
            'tree': [{'path': 'previews', 'mode': '040000', 'type': 'tree', 'sha': directory}]},
        prefix + '/git/trees/' + directory: {'sha': directory, 'truncated': False,
            'tree': [{'path': 'definition.json', 'mode': mode, 'type': 'blob', 'sha': blob, 'size': len(raw)}]},
        prefix + '/contents/' + row['sourcePath'] + '?ref=' + row['sourceSha']: {
            'path': row['sourcePath'], 'type': 'file', 'encoding': 'base64', 'sha': blob, 'size': len(raw),
            'content': base64.b64encode(raw).decode()}}


class Keycloak:
    def __init__(self):
        self.rows, self.deleted = {}, []

    def __call__(self, action, value):
        if action == 'find':
            return [copy.deepcopy(row) for row in self.rows.values() if row['clientId'] == value]
        if action == 'create':
            self.rows['owned-client-uuid'] = dict(copy.deepcopy(value), id='owned-client-uuid')
        if action == 'update':
            self.rows[value['id']] = copy.deepcopy(value)
        if action == 'delete':
            self.deleted.append(value)
            del self.rows[value]


class PrivatePreviewGit:
    """Synthetic Git server with response loss after owned writes."""
    def __init__(self):
        self.main, self.head, self.last_head = 'b' * 40, None, None
        self.commits, self.trees, self.writes = {}, {}, []
        self.number, self.closed, self.fail = None, False, None
        self.branch = ''
        self.race_head, self.graphql_result, self.retain_ref = None, NotImplemented, False
        self.repository_id, self.repository_node = 123, 'R_synthetic_private'

    def request(self, method, path, body=None, missing=False):
        if method != 'GET':
            self.writes.append((method, path, copy.deepcopy(body)))
        def written(kind, result):
            if self.fail == kind:
                self.fail = None
                raise RuntimeError('synthetic lost response')
            return result
        if path == 'repos/example/private':
            return {'full_name': 'example/private', 'private': True, 'fork': False, 'default_branch': 'main',
                    'id': self.repository_id, 'node_id': self.repository_node}
        if path == 'graphql':
            if self.graphql_result is not NotImplemented:
                return self.graphql_result
            value = body['variables']['input']
            updates = value['refUpdates']
            if (value['repositoryId'] != self.repository_node or len(updates) != 1 or
                    updates[0]['name'] != 'refs/heads/' + self.branch or updates[0]['afterOid'] != '0' * 40 or
                    updates[0]['force'] is not False):
                raise AssertionError('Fixture atomic deletion scope differs')
            if self.race_head is not None:
                self.head = self.race_head
            if updates[0]['beforeOid'] != self.head:
                return {'errors': [{'message': 'synthetic private provider mismatch'}], 'data': {'updateRefs': None}}
            if not self.retain_ref:
                self.head = None
            return written('delete', {'data': {'updateRefs': {'clientMutationId': value['clientMutationId']}}})
        if path.endswith('/git/ref/heads/main'):
            return {'object': {'sha': self.main}}
        if '/git/ref/heads/' in path:
            return {'object': {'sha': self.head}} if self.head else None
        if method == 'POST' and path.endswith('/git/trees'):
            name = str(len(self.trees))
            self.trees[name] = body['tree'][0]['content'].encode()
            return {'sha': name}
        if method == 'POST' and path.endswith('/git/commits'):
            name = format(len(self.commits) + 1, '040x')
            self.commits[name] = self.trees[body['tree']]
            return {'sha': name}
        if '/git/commits/' in path:
            return {'tree': {'sha': 'base-tree'}}
        if method == 'POST' and path.endswith('/git/refs'):
            self.head = self.last_head = body['sha']
            self.branch = body['ref'].removeprefix('refs/heads/')
            return written('ref', {})
        if method == 'PATCH' and '/git/refs/heads/' in path:
            if body.get('force') is not False:
                raise AssertionError('Fixture attempted a forced ref')
            self.head = self.last_head = body['sha']
            return written('advance', {})
        if method == 'DELETE' and '/git/refs/heads/' in path:
            self.head = None
            return written('delete', {})
        if '/contents/' in path:
            return {'content': base64.b64encode(self.commits[path.split('?ref=')[1]]).decode()}
        if '/compare/' in path:
            return {'total_commits': 1, 'files': [{'filename': 'previews/definition.json', 'status': 'added'}]}
        if '/pulls?' in path:
            return [self.pull()] if self.number else []
        if method == 'POST' and path.endswith('/pulls'):
            self.number = 7
            return written('pull', self.pull())
        if method == 'PATCH' and '/pulls/' in path:
            self.closed = True
            return written('close', self.pull())
        if '/pulls/' in path:
            return self.pull()
        raise AssertionError('Unexpected fixture API operation')

    def pull(self):
        return {'number': self.number, 'state': 'closed' if self.closed else 'open', 'merged': False, 'draft': False,
                'head': {'sha': self.head or self.last_head, 'ref': self.branch, 'repo': {'id': 123, 'fork': False}},
                'base': {'ref': 'main', 'repo': {'id': 123}}}


class CatalogGit:
    """Native private publisher fixture with exact catalog blobs and lost replies."""
    def __init__(self):
        self.main, self.branch, self.head = '1' * 40, None, None
        self.documents = {self.main: (json.dumps({'catalog': catalog([])}, sort_keys=True, indent=2) + '\n').encode()}
        self.commits, self.blobs, self.trees = {}, {}, {}
        self.number, self.merged, self.closed, self.fail = None, False, False, None
        self.pull_body = None
        self.writes = []
        self.source_pulls = {}

    def request(self, method, path, body=None, missing=False):
        import hashlib
        from playbooks.argocd.files.github_setup import MARKER
        if method == 'GET' and path in self.source_pulls:
            return copy.deepcopy(self.source_pulls[path])
        if method != 'GET': self.writes.append((method, path, copy.deepcopy(body)))
        def written(kind, result):
            if self.fail == kind:
                self.fail = None
                raise RuntimeError('synthetic lost response')
            return result
        repo = {'id': 123, 'node_id': 'R_catalog', 'full_name': 'example/private', 'private': True,
                'fork': False, 'default_branch': 'main', 'description': MARKER + 'private-config'}
        if path == 'repos/example/private': return repo
        if path.endswith('/git/ref/heads/main'): return {'object': {'sha': self.main}}
        if '/git/ref/heads/' in path: return {'object': {'sha': self.head}} if self.head else None
        if '/contents/' in path:
            raw = self.documents.get(path.split('?ref=')[1])
            if raw is None: return None
            return {'type': 'file', 'encoding': 'base64', 'content': base64.b64encode(raw).decode(),
                    'sha': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
        if path.endswith('/git/blobs'):
            sha = format(len(self.blobs) + 10, '040x'); self.blobs[sha] = body['content'].encode(); return {'sha': sha}
        if path.endswith('/git/trees'):
            sha = format(len(self.trees) + 20, '040x'); self.trees[sha] = self.blobs[body['tree'][0]['sha']]; return {'sha': sha}
        if path.endswith('/git/commits'):
            sha = format(len(self.commits) + 30, '040x')
            self.commits[sha] = {'sha': sha, 'parents': [{'sha': value} for value in body['parents']], 'tree': {'sha': body['tree']}}
            self.documents[sha] = self.trees[body['tree']]; return {'sha': sha}
        if '/git/commits/' in path: return self.commits.get(path.rsplit('/', 1)[1], {'tree': {'sha': 'base-tree'}})
        if path.endswith('/git/refs'):
            self.head, self.branch = body['sha'], body['ref'].removeprefix('refs/heads/')
            return written('ref', {})
        if '/compare/' in path: return {'total_commits': 1, 'files': [{'filename': 'previews/catalog.json', 'status': 'modified'}]}
        if '/pulls?' in path: return [self.pull(repo)] if self.number and ('state=all' in path or not self.closed) else []
        if path.endswith('/pulls'):
            self.number, self.pull_body = 9, body['body']; return written('pull', self.pull(repo))
        if path.endswith('/merge'):
            self.merged = self.closed = True; self.main = self.head
            return written('merge', {'merged': True, 'sha': self.main})
        if '/files?' in path: return [{'filename': 'previews/catalog.json', 'status': 'modified'}]
        if '/pulls/' in path:
            if method == 'PATCH': self.closed = True
            return self.pull(repo)
        if path == 'graphql':
            value = body['variables']['input']; update = value['refUpdates'][0]
            if update['beforeOid'] != self.head: return {'errors': [{'message': 'changed'}]}
            self.head = None
            return written('delete', {'data': {'updateRefs': {'clientMutationId': value['clientMutationId']}}})
        raise AssertionError('Unexpected synthetic catalog operation')

    def pull(self, repo):
        return {'number': self.number, 'state': 'closed' if self.closed else 'open', 'draft': False,
            'body': self.pull_body,
            'merged': self.merged, 'merge_commit_sha': self.main if self.merged else None,
            'head': {'sha': self.head, 'ref': self.branch, 'repo': repo},
            'base': {'sha': self.commits.get(self.head, {}).get('parents', [{'sha': self.main}])[0]['sha'], 'ref': 'main', 'repo': repo}}


def orphan_pair(api):
    nonce = 'e' * 32
    state = {'nonce': nonce, 'approvals': {}, 'pulls': {}}
    for slot, number in (('c', 17), ('d', 18)):
        row = approval(slot * 32)
        row.update(repository='example/private', pullRequest=number,
            definition={'profile': 'synthetic', 'message': 'synthetic fixture ' + slot + ' revision 0'})
        row['sourceDigest'] = digest(canonical(row['definition']))
        state['approvals'][slot] = {'instance': row['instance'], 'head': row['sourceSha'],
            'platform': row['platformRevision'], 'row': row,
            'artifact': {'instance': row['instance'], 'sha256': digest(canonical(row))}}
        receipt = state['pulls'][slot] = {'repository': row['repository'], 'repositoryId': row['repositoryId'],
            'number': number, 'head': row['sourceSha'], 'branch': 'cloudlab-preview-fixture/' + nonce + '/' + slot,
            'base': '1' * 40, 'closed': False, 'deleted': False, 'pending': None}
        source = pull(row); source['head']['ref'] = receipt['branch']; source['base']['ref'] = 'main'
        api.source_pulls['repos/example/private/pulls/' + str(number)] = source
    settings = catalog([record['row'] for record in state['approvals'].values()])
    settings['privateDiscovery'] = True
    api.documents[api.main] = (json.dumps({'catalog': settings}, sort_keys=True, indent=2) + '\n').encode()
    return state


def lifecycle_observation():
    from playbooks.previews.files.resources import resources, private_route
    from playbooks.keycloak.files.preview_clients import representation
    from playbooks.previews.tests.evidence_runtime import resource
    row, platform = approval(), 'https://github.com/example/platform.git'
    settings = catalog([row]); n = names(row); state_uid = 'runtime-state'
    declarations = resources(row, settings, platform, state_uid) + [private_route(row, settings, state_uid)]
    appset = next(obj for obj in declarations if obj['kind'] == 'ApplicationSet')
    declarations.append({'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
        'metadata': copy.deepcopy(appset['spec']['template']['metadata']), 'spec': copy.deepcopy(appset['spec']['template']['spec']),
        'status': {'sync': {'status': 'Synced', 'revision': row['platformRevision']}, 'health': {'status': 'Healthy'}}})
    declarations[-1]['metadata']['namespace'] = 'argocd'
    common = copy.deepcopy(declarations[-1]['metadata']); common.update(name='preview', namespace=n['namespace'])
    declarations.extend([
        {'apiVersion': 'v1', 'kind': 'Service', 'metadata': copy.deepcopy(common)},
        {'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': copy.deepcopy(common)},
        {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': copy.deepcopy(common), 'status': {'readyReplicas': 1},
         'spec': {'template': {'spec': {'automountServiceAccountToken': False, 'containers': [{'image': IMAGE, 'env': [
             {'name': 'CLOUDLAB_SOURCE_SHA', 'value': row['sourceSha']}, {'name': 'PREVIEW_MESSAGE', 'value': row['definition']['message']}]}]}}}}])
    objects, receipts = {}, []
    for obj in declarations:
        meta = obj['metadata']; meta.update(uid=obj['kind']+'-'+meta['name'], resourceVersion='1')
        objects[resource(obj['kind'], obj['apiVersion']), meta['name'], meta.get('namespace')] = obj
        receipts.append({'key': [obj['apiVersion'], obj['kind'], meta.get('namespace', ''), meta['name']], 'uid': meta['uid']})
    runtime = {'approval': row, 'approvalDigest': digest(canonical(row)), 'phase': 'active', 'resources': receipts}
    lifecycle = {'metadata': {'uid': state_uid}, 'data': {'state.json': json.dumps({'entries': {row['instance']: runtime}})}}
    client = dict(representation(row, settings), id='owned-client-uuid')
    identity = {'data': {'state.json': json.dumps({'entries': {row['instance']: dict(runtime, uuid=client['id'])}})}}
    objects['replicasets.apps', None, n['namespace']] = {'items': [{'metadata': {'uid': 'replica',
        'ownerReferences': [{'kind': 'Deployment', 'uid': 'Deployment-preview'}]}}]}
    objects['pods', None, n['namespace']] = {'items': [{'metadata': {'uid': 'pod', 'name': 'preview-pod',
        'labels': {'app.kubernetes.io/name': 'preview'}, 'ownerReferences': [{'kind': 'ReplicaSet', 'uid': 'replica'}]},
        'spec': {'automountServiceAccountToken': False}, 'status': {'phase': 'Running'}}]}
    return row, settings, lifecycle, identity, objects, client, platform


def generated_application(appset):
    obj = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
        'metadata': copy.deepcopy(appset['spec']['template']['metadata']),
        'spec': copy.deepcopy(appset['spec']['template']['spec'])}
    obj['metadata'].update(namespace='argocd', ownerReferences=[{
        'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet', 'name': appset['metadata']['name'],
        'uid': appset['metadata']['uid'], 'controller': True, 'blockOwnerDeletion': True}])
    return obj


class ResourceAPI:
    """Bounded native-object fixture, with server rejection and lost write replies."""
    def __init__(self):
        self.objects, self.writes, self.fail = {}, [], None

    def get(self, key):
        return copy.deepcopy(self.objects.get(tuple(key)))

    def create(self, desired):
        from playbooks.previews.files.kube import identity, APIError
        key = identity(desired)
        if key in self.objects: raise APIError(409)
        self.writes.append(('create', key))
        actual = copy.deepcopy(desired)
        actual['metadata'].update(uid='uid-' + str(len(self.writes)), resourceVersion='1')
        self.objects[key] = actual
        if self.fail == 'create': self.fail = None; raise RuntimeError('lost reply')
        return copy.deepcopy(actual)

    def replace(self, actual):
        from playbooks.previews.files.kube import identity
        key = identity(actual); previous = self.objects[key]
        if previous['metadata']['resourceVersion'] != actual['metadata']['resourceVersion']: raise ValueError('changed version')
        self.writes.append(('replace', key)); self.objects[key] = copy.deepcopy(actual)
        self.objects[key]['metadata']['resourceVersion'] = str(int(actual['metadata']['resourceVersion']) + 1)
        if self.fail == 'replace': self.fail = None; raise RuntimeError('lost reply')
        return self.get(key)

    def delete(self, key, uid, version, *, orphan=False):
        actual = self.objects[key]
        if actual['metadata']['uid'] != uid or actual['metadata']['resourceVersion'] != version: raise ValueError('changed delete precondition')
        self.writes.append(('delete', tuple(key))); del self.objects[key]
        if self.fail == 'delete': self.fail = None; raise RuntimeError('lost reply')

    def namespace_inventory(self, namespace):
        return [copy.deepcopy(actual) for key, actual in self.objects.items() if key[2] == namespace]


def probe_observation():
    from playbooks.previews.files import contract
    from playbooks.previews.files.resources import workload
    row, settings, lifecycle, _, objects, _, platform = lifecycle_observation()
    ns=names(row)['namespace']
    lifecycle['metadata']['labels']={'cloudlab.io/owner':contract.OWNER}
    objects['configmap',contract.APPROVALS,'argocd']={'metadata':{'labels':{'cloudlab.io/owner':contract.OWNER}},
        'data':{'catalog.json':json.dumps(settings)}}
    objects['configmap',contract.STATE,'argocd']=lifecycle
    objects['application.argoproj.io','cloudlab-previews','argocd']={'metadata':{'labels':{'cloudlab.io/owner':contract.OWNER}},
        'spec':{'sources':[{'repoURL':platform,'targetRevision':row['platformRevision']}]},
        'status':{'sync':{'revisions':[row['platformRevision']]},'health':{'status':'Healthy'}}}
    objects['service','cloudlab-istio','cloudlab-gateway-private']={'metadata':{'uid':'gateway-service',
        'ownerReferences':[{'kind':'Gateway','uid':'gateway-owner'}]},'spec':{'clusterIP':'10.43.0.1'}}
    objects['gateway.gateway.networking.k8s.io','cloudlab','cloudlab-gateway-private']={
        'metadata':{'uid':'gateway-owner'},'spec':{'gatewayClassName':'istio'}}
    objects['service','preview',ns]['spec']={'selector':{'app.kubernetes.io/name':'preview'},'clusterIP':'10.43.0.2',
        'ports':[{'port':8080,'targetPort':'http','protocol':'TCP'}]}
    deployment=objects['deployment.apps','preview',ns]
    deployment['spec']['template']['spec']['containers'][0]['command']=workload(row,settings)['command']
    pod=objects['pods',None,ns]['items'][0]
    pod['spec']=copy.deepcopy(deployment['spec']['template']['spec'])
    pod['status'].update(podIP='10.42.0.5',conditions=[{'type':'Ready','status':'True'}])
    objects['endpointslices.discovery.k8s.io',None,ns]={'items':[{'metadata':{'uid':'slice',
        'labels':{'kubernetes.io/service-name':'preview'},'ownerReferences':[{'kind':'Service','uid':'Service-preview'}]},
        'endpoints':[{'addresses':['10.42.0.5'],'conditions':{'ready':True},
            'targetRef':{'uid':pod['metadata']['uid'],'kind':'Pod','namespace':ns}}],
        'ports':[{'port':8080,'protocol':'TCP'}]}]}
    return row,objects


def probe_channel_child(mode='valid'):
    """Local child runs the real host protocol with synthetic external observations."""
    return 'MODE = ' + repr(mode) + '\n' + r'''
import json,os,sys,time
if MODE=='startup-refuse':raise SystemExit(23)
if MODE in ('missing','partial','malformed','stderr','queued'):
    request=json.loads(sys.stdin.buffer.readline(32769))
    if MODE=='missing':time.sleep(10)
    elif MODE=='partial':os.write(1,b'{"action":');time.sleep(10)
    elif MODE=='malformed':os.write(1,b'{"ready":true}\n');time.sleep(10)
    elif MODE=='stderr':os.write(2,b'private-diagnostic-sentinel'*1000);time.sleep(10)
    else:
        ready={'action':'ready','challenge':request['challenge'],'serverNonce':'d'*64,
            'revision':request['revision'],'digests':request['digests'],'assurance':'b'*64,'bindings':'c'*64,
            'namespaceUID':'namespace-uid','podUID':'pod-uid'}
        os.write(1,(json.dumps(ready)+'\n'+json.dumps({'unexpected':True})+'\n').encode());time.sleep(10)
    raise SystemExit(0)
from playbooks.previews.tests import probe_inspection as helper
probe={'Namespace':{'metadata':{'name':'synthetic','uid':'namespace-uid'}},
       'Pod':{'metadata':{'uid':'pod-uid'}},'Service':{'spec':{'clusterIP':'10.43.0.1'}}}
counter=[0];assurance_counter=[0]
def context(request):
    counter[0]+=1
    changed=(MODE=='target-change' and counter[0]>1) or (MODE=='ready-target-change' and counter[0]>=3) or (MODE=='post-target-change' and counter[0]>=4)
    return probe,[],('e'*64 if changed else 'c'*64)
def assurance():
    assurance_counter[0]+=1
    if MODE=='assurance-refuse':raise ValueError('private-diagnostic-sentinel')
    return 'e'*64 if MODE=='config-change' or MODE=='ready-assurance-change' and assurance_counter[0]>=3 else 'b'*64
def execute(frame,namespace,deadline):
    if frame['phase']=='preflight':
        if MODE=='preflight-refuse':raise ValueError('private-diagnostic-sentinel')
        assert frame['tokens']==[]
        return {'preflight':True}
    assert len(frame['tokens'])==2
    if MODE in ('ready-target-change','ready-assurance-change'):
        os.write(2,b'SECRET_PROBE_EXECUTED\n')
    return {'targets':[dict(control=True,gateway=True,podProtected=True,serviceProtected=True,serviceMode='blocked')]*2}
helper.context=context;helper.probe_state.assurance=assurance;helper.execute=execute
try:helper.main()
except Exception:raise SystemExit(1) from None
'''


def probe_assurance_observation(native='/usr/lib/openssh/sshd-session', pam='sshd', *, shell=False):
    """Synthetic Debian root session and existing local K3s observations."""
    server='forcecommand none\npermituserenvironment no\nloglevel INFO\nacceptenv LANG LC_* COLORTERM NO_COLOR\n'
    if pam is not None:server+='pamservicename '+pam+'\n'
    commands={('/usr/sbin/sshd','-T','-C','user=root,addr=100.64.0.1,laddr=100.64.0.2,lport=22'):server,
        ('dpkg','--verify','openssh-server','libpam-modules','libpam-runtime','bash'):'',
        ('dpkg-query','--search',native):'openssh-server: '+native+'\n',
        ('systemctl','show','k3s','--property=ExecStart','--value'):'/usr/local/bin/k3s server',
        ('systemctl','show','k3s','--property=MainPID','--value'):'500\n'}
    files={'/etc/passwd':'root:x:0:0:root:/root:/bin/bash\n', '/root/.bashrc':'[ -z "$PS1" ] && return\nexport HISTCONTROL=ignoreboth\n',
        '/etc/pam.d/sshd':'@include common-session\n','/etc/pam.d/common-session':'session required pam_unix.so\n',
        '/etc/pam.d/common-session-noninteractive':'session required pam_unix.so\n',
        '/etc/rancher/k3s/config.yaml':'write-kubeconfig-mode: "0600"\n',
        '/etc/rancher/k3s/k3s.yaml':json.dumps({'clusters':[{'cluster':{'server':'https://127.0.0.1:6443',
            'certificate-authority-data':'synthetic'}}],'users':[]}),'/proc/101/status':'PPid:\t100\n'}
    executables={'/proc/100/exe':native,'/proc/101/exe':'/usr/bin/bash'}
    cmdlines={'/proc/100/cmdline':b'sshd-session: root@notty\0','/proc/101/cmdline':
        b'/bin/bash\0-c\0python3 /opt/cloudlab/playbooks/previews/tests/probe_inspection.py\0',
        '/proc/500/cmdline':b'/usr/local/bin/k3s\0server\0'}
    return {'commands':commands,'files':files,'executables':executables,'cmdlines':cmdlines,'parent':101 if shell else 100}

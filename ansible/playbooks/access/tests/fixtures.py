"""In-memory provider for access reconciliation and identity tests."""
import copy


class Provider:
    def __init__(self):
        self.objects = {}
        self.config = {'config': {'ingress': [{'service': 'http_status:404'}]}}
        self.writes = []
        self.interrupt_create = False

    def collection(self, path):
        return [copy.deepcopy(v) for k, v in self.objects.items() if k.rsplit('/', 1)[0] == path]

    def request(self, method, path, document=None):
        if method != 'GET':
            self.writes.append((method, path))
        if path.endswith('/configurations'):
            if method == 'PUT':
                self.config = copy.deepcopy(document)
            return copy.deepcopy(self.config)
        if method == 'POST':
            identity = str(len(self.objects) + 1)
            value = dict(copy.deepcopy(document), id=identity)
            if path.endswith('/apps'):
                value['aud'] = 'fixture-audience'
            self.objects[path + '/' + identity] = value
            if self.interrupt_create:
                self.interrupt_create = False
                raise RuntimeError('connection lost after server committed creation')
            return copy.deepcopy(value)
        if method == 'PUT':
            self.objects[path].update(copy.deepcopy(document))
        return copy.deepcopy(self.objects[path])

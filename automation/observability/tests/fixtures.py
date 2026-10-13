"""Synthetic independent account and monitor responses."""
import copy

from automation.observability.uptimerobot import desired


class FakeAPI:
    def __init__(self):
        self.user = {'email': 'operator@example.com', 'monitorLimit': 50,
                     'activeSubscription': {'plan': 'FREE'}}
        self.contacts = [{'id': 7, 'type': 'Email', 'value': 'operator@example.com', 'status': 'Active'}]
        self.rows = []
        self.writes = []
        self.next_link = None
        self.next_id = 12

    def request(self, method, path, value=None):
        if method == 'GET':
            if path == 'user/me': return copy.deepcopy(self.user)
            if path == 'user/alert-contacts': return copy.deepcopy(self.contacts)
            if path == 'monitors?limit=50': return {'data': copy.deepcopy(self.rows), 'nextLink': self.next_link}
            raise AssertionError('Unexpected fixture read')
        self.writes.append((method, path, copy.deepcopy(value)))
        if method == 'POST':
            while any(row.get('id') == self.next_id for row in self.rows): self.next_id += 1
            self.rows.append(dict(value, id=self.next_id, status='STARTED'))
        elif method == 'PATCH':
            identifier = int(path.split('/')[-1])
            next(row for row in self.rows if row['id'] == identifier).update(value)
        elif method == 'DELETE':
            identifier = int(path.split('/')[-1])
            self.rows = [row for row in self.rows if row['id'] != identifier]
        else: raise AssertionError('Unexpected fixture mutation')


def existing(key='notes-health', url='https://notes.example.com/health', **overrides):
    return dict(desired(key, url, 7), id=12, status='UP', **overrides)

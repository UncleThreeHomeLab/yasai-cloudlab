"""Create the approved synthetic notes fixture without replacing user data."""
import hashlib
from pathlib import Path

from playbooks.data.files import control
from playbooks.data.files.s3 import S3Error

BODY = 'A synthetic note with a scoped PostgreSQL row and an S3 attachment.\n'
IDENTIFIER = 'cloudlab-demo-welcome'


def run():
    with control.locked():
        return seed()


def seed():
    values = control.settings()
    migration = control.identity(values['migrationRole'])
    schema = Path(__file__).with_name('schema.sql').read_text()
    control.sql('SET ROLE ' + migration + ';\n' + schema, values['database'])
    expected = 'attachment_key:text,body:text,id:text,title:text'
    actual = control.sql("SELECT string_agg(column_name||':'||data_type,',' ORDER BY column_name) FROM information_schema.columns WHERE table_schema='public' AND table_name='notes';", values['database'])
    if actual != expected:
        raise RuntimeError('Existing notes table is incompatible; user data retained')
    if control.sql("SELECT count(*) FROM public.notes WHERE id='" + IDENTIFIER + "';", values['database']) == '1':
        return {'changed': False, 'existing_note_preserved': True}
    digest = hashlib.sha256(BODY.encode()).hexdigest()
    key = 'notes/' + digest + '.txt'
    client = control.s3(False)
    try:
        actual = client.request('GET', values['bucket'], key)
        if actual['sha256'] != digest:
            raise RuntimeError('Existing synthetic object differs; overwrite refused')
    except S3Error as error:
        if error.status != 404: raise
        client.request('PUT', values['bucket'], key, data=BODY.encode())
    quote = lambda value: "'" + value.replace("'", "''") + "'"
    control.sql('SET ROLE ' + migration + '; INSERT INTO public.notes(id,title,body,attachment_key) VALUES (' +
                ','.join(map(quote, (IDENTIFIER, 'Welcome to CloudLab', BODY, key))) + ') ON CONFLICT(id) DO NOTHING;', values['database'])
    return {'changed': True, 'existing_data_preserved': True}

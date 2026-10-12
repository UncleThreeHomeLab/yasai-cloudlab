const settings = await fetch('/settings.json').then(r => r.json());
document.querySelector('#operations').hidden = !settings.operations;
const status = document.querySelector('#status');
let token;
const encode = bytes => btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
const random = () => encode(crypto.getRandomValues(new Uint8Array(32)));
const callback = location.origin + '/callback';
const issuer = new URL(settings.issuer);
if (issuer.protocol !== 'https:') throw new Error('HTTPS identity required');
const endpoint = path => settings.issuer + '/protocol/openid-connect/' + path;

document.querySelector('#login').onclick = async () => {
  const transaction = {state: random(), nonce: random(), verifier: random(), created: Date.now(), returnPath: location.pathname === '/operations' ? '/operations' : '/'};
  sessionStorage.setItem('notes-login', JSON.stringify(transaction));
  const challenge = encode(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(transaction.verifier))));
  const parameters = new URLSearchParams({client_id: settings.client, redirect_uri: callback, response_type: 'code',
    scope: settings.scopes.join(' '), state: transaction.state, nonce: transaction.nonce, code_challenge: challenge, code_challenge_method: 'S256'});
  location.assign(endpoint('auth') + '?' + parameters);
};

async function acceptLogin() {
  const parameters = new URLSearchParams(location.search);
  if (!parameters.has('code')) return;
  const saved = sessionStorage.getItem('notes-login');
  sessionStorage.removeItem('notes-login');
  history.replaceState({}, '', '/');
  if (!saved) throw new Error('Missing login transaction');
  const transaction = JSON.parse(saved);
  history.replaceState({}, '', transaction.returnPath === '/operations' ? '/operations' : '/');
  if (parameters.get('state') !== transaction.state || !Number.isFinite(transaction.created) || transaction.created > Date.now() || Date.now() - transaction.created > 300000) throw new Error('Login state rejected');
  const response = await fetch(endpoint('token'), {method: 'POST', credentials: 'omit',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: new URLSearchParams({grant_type: 'authorization_code',
      client_id: settings.client, redirect_uri: callback, code: parameters.get('code'), code_verifier: transaction.verifier})});
  if (!response.ok) throw new Error('Login rejected');
  const result = await response.json();
  const parts = result.id_token.split('.');
  const decode = value => Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4-value.length%4)%4)), c => c.charCodeAt(0));
  const header = JSON.parse(new TextDecoder().decode(decode(parts[0])));
  const claims = JSON.parse(new TextDecoder().decode(decode(parts[1])));
  if (header.alg !== 'RS256' || header.typ !== 'JWT' || header.crit || claims.typ !== 'ID') throw new Error('ID token rejected');
  const keys = await fetch(endpoint('certs'), {credentials: 'omit'}).then(r => r.json());
  const matches = keys.keys.filter(k => k.kid === header.kid && k.kty === 'RSA' && k.use === 'sig' && k.alg === 'RS256');
  if (matches.length !== 1) throw new Error('Signing key rejected');
  const key = await crypto.subtle.importKey('jwk', matches[0], {name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'}, false, ['verify']);
  if (!await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, decode(parts[2]), new TextEncoder().encode(parts[0]+'.'+parts[1]))) throw new Error('Signature rejected');
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  const now = Date.now()/1000;
  if (claims.iss !== settings.issuer || !audiences.includes(settings.client) || (audiences.length>1 && claims.azp!==settings.client) ||
      claims.nonce !== transaction.nonce || !Number.isFinite(claims.exp) || claims.exp <= now ||
      !Number.isFinite(claims.iat) || claims.iat > now || (claims.nbf ?? 0) > now || typeof claims.sub !== 'string' || !claims.sub) throw new Error('ID claims rejected');
  token = result.access_token;
  // Tokens stay in memory. Reload starts a new SSO transaction; no refresh token storage.
}

async function load() {
  if (!token) return;
  const operations = location.pathname === '/operations';
  const response = await fetch(operations ? '/api/operations' : '/api/notes', {headers:{Authorization:'Bearer '+token}});
  if (!response.ok) throw new Error(response.status===403 ? 'This role cannot access this view.' : 'Session expired. Sign in again.');
  const result = await response.json();
  status.textContent = operations ? 'Operations: data retained; service healthy.' : 'Signed in. Notes and attachments use scoped credentials.';
  for (const note of result.notes ?? []) {
    const card = document.createElement('article');
    const heading = document.createElement('h2'); heading.textContent = note.title;
    const text = document.createElement('p'); text.textContent = note.body;
    card.append(heading,text); document.querySelector('#notes').append(card);
  }
}
document.querySelector('#compose').onsubmit = async event => {
  event.preventDefault();
  if (!token) {status.textContent='Sign in first.'; return;}
  const values = new FormData(event.target);
  const response = await fetch('/api/notes',{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},
    body:JSON.stringify({id:crypto.randomUUID(),title:values.get('title'),body:values.get('body')})});
  status.textContent = response.ok ? 'Note saved.' : response.status===403 ? 'Writer role required.' : 'Save failed. Existing data retained.';
};
try {await acceptLogin(); await load();} catch(error) {status.textContent=error.message;}

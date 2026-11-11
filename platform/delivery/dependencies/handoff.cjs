// Bounded single-use handoff shared only with the trusted credential owner.
//
// The named trusted automation (Compose maintenance-handoff, D47) runs this
// consumer on schedule with the owner-provisioned writer token in
// RENOVATE_TOKEN; the repository never stores it and the value only reaches
// the writer on stdin. Raw logs stay in tmpfs. Modes: once (default, one
// 120s poll for ad-hoc operator use) or loop (consume until terminated).
const fs = require('node:fs');
const {spawnSync} = require('node:child_process');

let last = null;

function consume() {
  if (!fs.existsSync('/handoff/request.json')) return false;
  const input = fs.readFileSync('/handoff/request.json', 'utf8');
  if (input === last) return false;
  last = input;
  if (input.length > 16384) {
    process.exitCode = 1;
    return true;
  }
  let scoped = '';
  try {
    const token = process.env.RENOVATE_TOKEN || '';
    if (!token || /\s/.test(token)) throw new Error('writer token missing');
    const request = JSON.parse(input);
    request.token = token;
    scoped = JSON.stringify(request);
    if (scoped.length > 16384) throw new Error('scoped request exceeds 16 KiB');
  } catch {
    scoped = '';
  }
  const result = scoped ? spawnSync(process.execPath, ['/trusted/renovate-run.cjs'], {
    input: scoped, env: {PATH: process.env.PATH}, encoding: 'utf8', timeout: 1810000,
    maxBuffer: 16384
  }) : {status: 1, stdout: ''};
  scoped = '';
  // Raw Renovate logs stay in tmpfs. Only its allowlisted result leaves.
  if (result.status === 0 && result.stdout.length < 1024) {
    fs.writeFileSync('/handoff/result.tmp', result.stdout, {mode: 0o600});
    fs.renameSync('/handoff/result.tmp', '/handoff/result.json');
  } else {
    let operation = '';
    try { operation = JSON.parse(input).operation; } catch {}
    fs.writeFileSync('/handoff/result.tmp', JSON.stringify({operation, passed: false}), {mode: 0o600});
    fs.renameSync('/handoff/result.tmp', '/handoff/result.json');
    process.exitCode = 1;
  }
  return true;
}

const mode = process.argv[2] || 'once';
if (mode !== 'once' && mode !== 'loop') {
  process.stderr.write('handoff: requires once or loop\n');
  process.exitCode = 1;
  return;
}
const deadline = mode === 'once' ? Date.now() + 120000 : Infinity;
const poll = setInterval(() => {
  if (Date.now() > deadline) {
    clearInterval(poll);
    process.exitCode = 1;
  } else if (consume()) {
    if (mode === 'once') clearInterval(poll);
  }
}, 250);

// Scheduled invocation for the credential-free dependency orchestrator.
//
// Loops on MAINTENANCE_INTERVAL, resolves the exact base SHA from a clean
// checkout, then runs orchestrate.cjs; cadence gating stays inside the
// orchestrator. Never handles the writer token: due groups wait on the
// handoff directory for the trusted credential owner (see README.md).
const {spawnSync} = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const HERE = __dirname;
const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const BASE_PATTERN = /^(main|cloudlab-maintenance-fixture\/[a-z0-9-]{1,64})$/;
const SHA_PATTERN = /^[0-9a-f]{40}$/;

const fail = message => { process.stderr.write(`schedule: ${message}\n`); process.exitCode = 1; };

function configuration() {
  const raw = process.env.MAINTENANCE_INTERVAL || '3600';
  const interval = Number(raw);
  if (!Number.isInteger(interval)) return void fail('MAINTENANCE_INTERVAL must be seconds');
  if (interval < 60 || interval > 86400) {
    return void fail('MAINTENANCE_INTERVAL must be between 60 and 86400 seconds');
  }
  const repository = process.env.MAINTENANCE_REPOSITORY || 'UncleThreeHomeLab/yasai-cloudlab';
  if (!REPOSITORY_PATTERN.test(repository)) return void fail('MAINTENANCE_REPOSITORY must be owner/name');
  const base = process.env.MAINTENANCE_BASE || 'main';
  if (!BASE_PATTERN.test(base)) return void fail('MAINTENANCE_BASE must be main or a cloudlab-maintenance-fixture branch');
  if (process.exitCode) return null;
  return {interval, repository, base,
    gitDir: process.env.MAINTENANCE_GIT_DIR || path.resolve(HERE, '..', '..', '..'),
    stateDir: process.env.MAINTENANCE_STATE_DIR || '/maintenance/state'};
}

function reviewedBase(gitDir) {
  const git = ['git', '--no-optional-locks', '-c', `safe.directory=${gitDir}`, '-C', gitDir];
  const head = spawnSync(git[0], [...git.slice(1), 'rev-parse', 'HEAD'],
    {encoding: 'utf8', timeout: 30000});
  const dirty = spawnSync(git[0], [...git.slice(1), 'status', '--porcelain'],
    {encoding: 'utf8', timeout: 60000});
  if (head.status !== 0 || dirty.status !== 0) throw new Error('base revision unavailable; refused');
  if (dirty.stdout.trim() || !SHA_PATTERN.test(head.stdout.trim())) {
    throw new Error('checkout must be clean at a commit; refused');
  }
  return head.stdout.trim();
}

function cycle(config, forwarded) {
  const baseSha = reviewedBase(config.gitDir);
  fs.mkdirSync(config.stateDir, {recursive: true});
  const result = spawnSync(process.execPath, [path.join(HERE, 'orchestrate.cjs'),
    '--repository', config.repository, '--base', config.base, '--base-sha', baseSha,
    '--state', path.join(config.stateDir, 'maintenance-state.json'),
    '--receipts', path.join(config.stateDir, 'receipts'), ...forwarded],
    {stdio: 'inherit', timeout: 5400000});
  if (result.error) throw result.error;
  const status = {ok: result.status === 0, baseSha, at: new Date().toISOString()};
  const target = path.join(config.stateDir, 'status.json');
  fs.writeFileSync(`${target}.tmp`, JSON.stringify(status), {mode: 0o600});
  fs.renameSync(`${target}.tmp`, target);
  process.stdout.write(JSON.stringify({scheduler: 'dependency-maintenance', ...status}) + '\n');
  return status;
}

function main() {
  const [mode, ...forwarded] = process.argv.slice(2);
  if (mode !== 'once' && mode !== 'loop') return void fail('requires once or loop');
  const config = configuration();
  if (!config) return;
  if (mode === 'once') {
    try {
      if (!cycle(config, forwarded).ok) process.exitCode = 1;
    } catch (error) {
      fail(error.message);
    }
    return;
  }
  while (true) {
    try {
      cycle(config, forwarded);
    } catch (error) {
      process.stderr.write(`schedule: ${error.message}\n`);
    }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, config.interval * 1000);
  }
}

main();

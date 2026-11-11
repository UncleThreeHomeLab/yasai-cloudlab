// Scheduled trusted orchestrator for dependency maintenance.
//
// Runs under the maintenance policy: validates maintenance.yaml (schema-
// equivalent checks, fail closed), resolves each group's owner against
// owners.json, gates on cadence, then executes the existing stages in fixed
// order per due group: qualify -> propose -> record.
//
// Credential-free: this script never accepts, stores, or forwards a writer
// token. The propose stage writes a token-free request to the handoff
// directory; the trusted credential owner merges the token out of band,
// runs the writer (handoff.cjs -> renovate-run.cjs), and returns the
// allowlisted result. Candidate code never executes in this process.
// No merge or branch-prune code paths exist here by design.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {spawnSync} = require('node:child_process');

// ponytail: monthly cadence is a fixed 30-day window, not calendar months;
// upgrade to calendar months only if a group needs month-boundary runs.
const CADENCE_SECONDS = {daily: 86400, weekly: 604800, monthly: 2592000};
const HANDOFF_DIR = process.env.CLOUDLAB_HANDOFF_DIR || '/handoff';
const TOOLCHAIN_FILE = process.env.CLOUDLAB_TOOLCHAIN_FILE || '/toolchain.json';
const REQUEST_BYTES = 16384;
const QUALIFY_TIMEOUT_MS = 600000;
const PROPOSE_TIMEOUT_MS = 1800000;
const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const BASE_PATTERN = /^(main|cloudlab-maintenance-fixture\/[a-z0-9-]{1,64})$/;
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const OPERATION_PATTERN = /^[a-f0-9]{32}$/;

const fail = message => { process.stderr.write(`orchestrate: ${message}\n`); process.exitCode = 1; };

// Strict parser for the fixed maintenance.yaml shape. Anything outside the
// exact key/indentation ladder fails closed; this enforces the same rules as
// maintenance.schema.json (required keys, consts, enums, lengths, ranges,
// additionalProperties: false) without a YAML dependency.
function parsePolicy(text) {
  if (text.length > 65536) throw new Error('policy exceeds 64 KiB');
  const root = {};
  let groups = null;
  let current = null;
  let section = null;
  const seenRoot = new Set();
  const seenGroup = [];
  const lines = text.split('\n');
  for (let index = 0; index < lines.length; index++) {
    const raw = lines[index].replace(/\r$/, '');
    if (/^\s*(#|$)/.test(raw)) continue;
    if (/^\t| \t|\t /.test(raw) || / $/.test(raw)) throw new Error(`policy line ${index + 1}: bad whitespace`);
    const indent = raw.match(/^ */)[0].length;
    const body = raw.slice(indent);
    if (indent === 0) {
      const key = body.endsWith(':') ? body.slice(0, -1) : null;
      if (key !== 'maintenance' || seenRoot.has(key)) throw new Error(`policy line ${index + 1}: expected 'maintenance:'`);
      seenRoot.add(key);
      section = 'maintenance';
      continue;
    }
    if (section !== 'maintenance') throw new Error(`policy line ${index + 1}: content outside maintenance`);
    if (indent === 2) {
      if (body === 'groups:') {
        if (groups) throw new Error(`policy line ${index + 1}: duplicate groups`);
        groups = [];
        continue;
      }
      if (body.startsWith('groups')) throw new Error(`policy line ${index + 1}: groups must be a block list`);
      const match = body.match(/^(automerge|pruneBranches): (.*)$/);
      if (!match || seenRoot.has(match[1])) throw new Error(`policy line ${index + 1}: unexpected key`);
      if (match[2] !== 'false') throw new Error(`policy line ${index + 1}: ${match[1]} must be false`);
      seenRoot.add(match[1]);
      root[match[1]] = false;
      continue;
    }
    if (indent !== 4 && indent !== 6) throw new Error(`policy line ${index + 1}: bad indentation`);
    if (!groups) throw new Error(`policy line ${index + 1}: group entry before groups`);
    if (indent === 4 && body.startsWith('- owner: ')) {
      current = {owner: body.slice('- owner: '.length)};
      if (current.owner.length < 1 || current.owner.length > 128 || /['"]/.test(current.owner)) {
        throw new Error(`policy line ${index + 1}: owner must be 1..128 unquoted characters`);
      }
      groups.push(current);
      seenGroup.push(new Set(['owner']));
      if (groups.length > 32) throw new Error('policy allows at most 32 groups');
      continue;
    }
    if (indent === 6 && current) {
      const match = body.match(/^(cadence|proposal|qualification): (.+)$/);
      if (!match || seenGroup[seenGroup.length - 1].has(match[1])) {
        throw new Error(`policy line ${index + 1}: unexpected group key`);
      }
      seenGroup[seenGroup.length - 1].add(match[1]);
      current[match[1]] = match[2];
      continue;
    }
    throw new Error(`policy line ${index + 1}: bad indentation or key`);
  }
  if (!groups || groups.length < 1) throw new Error('policy needs at least one group');
  for (const group of groups) {
    if (!CADENCE_SECONDS[group.cadence]) throw new Error(`owner ${group.owner}: bad cadence`);
    if (group.proposal !== 'draft') throw new Error(`owner ${group.owner}: proposal must be draft`);
    if (group.qualification !== 'owner-defined') throw new Error(`owner ${group.owner}: qualification must be owner-defined`);
  }
  if (root.automerge !== false || root.pruneBranches !== false) throw new Error('policy needs automerge/pruneBranches false');
  return {maintenance: {groups, automerge: false, pruneBranches: false}};
}

function readJson(file, maxBytes, label) {
  const text = fs.readFileSync(file, 'utf8');
  if (text.length > maxBytes) throw new Error(`${label} exceeds ${maxBytes} bytes`);
  return JSON.parse(text);
}

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function atomicJson(file, value) {
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value), {mode: 0o600});
  fs.renameSync(tmp, file);
}

function checkGuardrails(renovate) {
  const force = renovate && renovate.force;
  if (!force || force.draftPR !== true || force.automerge !== false ||
      force.platformAutomerge !== false || force.pruneStaleBranches !== false ||
      force.autoApprove !== false) {
    throw new Error('renovate force guardrails must pin draft-only, no automerge, no prune');
  }
}

function resolveOwner(owners, name) {
  const entry = owners && owners.owners && owners.owners[name];
  if (!entry) return null;
  for (const key of ['sources', 'companions', 'nativeDependencies']) {
    if (!Array.isArray(entry[key]) || entry[key].some(item => typeof item !== 'string' || !item)) return null;
  }
  const ownerPaths = [...entry.sources, ...entry.companions];
  if (ownerPaths.length === 0 || entry.nativeDependencies.length === 0) return null;
  return {ownerPaths, dependencies: [...entry.nativeDependencies]};
}

function loadState(file) {
  if (!fs.existsSync(file)) return {version: 1, lastRun: {}};
  const state = readJson(file, 65536, 'state');
  if (!state || state.version !== 1 || !state.lastRun || typeof state.lastRun !== 'object') {
    throw new Error('state file corrupt; delete it to reschedule from scratch');
  }
  return state;
}

function runQualify(stagesDir, image) {
  const result = spawnSync(process.execPath, [path.join(stagesDir, 'qualify.cjs')], {
    encoding: 'utf8', timeout: QUALIFY_TIMEOUT_MS, maxBuffer: 1024 * 1024,
    env: {PATH: process.env.PATH, HOME: process.env.HOME || '/tmp/home',
      DEPENDENCY_RENOVATE_IMAGE: image}
  });
  if (result.status !== 0) return false;
  try {
    return JSON.parse(result.stdout.trim()).passed === true;
  } catch {
    return false;
  }
}

function runPropose(request, timeoutMs) {
  const body = JSON.stringify(request);
  if (body.length > REQUEST_BYTES) throw new Error('handoff request exceeds 16 KiB');
  fs.mkdirSync(HANDOFF_DIR, {recursive: true});
  fs.rmSync(path.join(HANDOFF_DIR, 'result.json'), {force: true});
  const target = path.join(HANDOFF_DIR, 'request.json');
  fs.writeFileSync(`${target}.tmp`, body, {mode: 0o600});
  fs.renameSync(`${target}.tmp`, target);
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(path.join(HANDOFF_DIR, 'result.json'))) {
      const result = readJson(path.join(HANDOFF_DIR, 'result.json'), 1024, 'handoff result');
      if (result.operation !== request.operation) throw new Error('handoff result operation mismatch');
      for (const key of ['headSha', 'baseSha']) {
        if (result[key] !== undefined && result[key] !== null && !SHA_PATTERN.test(result[key])) {
          throw new Error(`handoff result ${key} is not a commit SHA`);
        }
      }
      return {passed: result.passed === true, headSha: result.headSha || null,
        baseSha: result.baseSha || null};
    }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 250);
  }
  throw new Error('handoff result timeout; trusted writer gave no result');
}

function readyCheck(receipt, files, baseSha) {
  for (const [key, file] of Object.entries(files)) {
    if (receipt.bindings[key] !== sha256File(file)) return {passed: false, reason: `stale ${key}`};
  }
  if (receipt.repository == null || receipt.base == null) return {passed: false, reason: 'receipt missing bindings'};
  if (receipt.baseSha !== baseSha) return {passed: false, reason: 'stale base SHA'};
  return {passed: true};
}

function parseArgs(argv) {
  const args = {positional: []};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--') && argv[i].includes('=')) {
      const [key, value] = argv[i].split(/=(.+)/);
      args[key.slice(2)] = value;
    } else if (argv[i].startsWith('--')) {
      args[argv[i].slice(2)] = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
    } else {
      args.positional.push(argv[i]);
    }
  }
  return args;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const here = __dirname;
  const files = {
    policy: args.policy || path.join(here, 'maintenance.yaml'),
    owners: args.owners || path.join(here, 'owners.json'),
    renovate: args.renovate || path.join(here, 'renovate.json'),
    lock: args.lock || path.join(here, 'image.lock.json')
  };
  const now = args.now ? Number(args.now) : Math.floor(Date.now() / 1000);
  if (!Number.isInteger(now) || now <= 0) return void fail('bad --now epoch');
  const baseSha = args['base-sha'];
  if (typeof baseSha !== 'string' || !SHA_PATTERN.test(baseSha)) {
    return void fail('--base-sha with the exact tested base commit is required');
  }
  let policy;
  try {
    policy = parsePolicy(fs.readFileSync(files.policy, 'utf8'));
  } catch (error) {
    return void fail(`invalid policy: ${error.message}`);
  }
  let ownersDoc;
  let renovateDoc;
  let lockDoc;
  try {
    ownersDoc = readJson(files.owners, 2 * 1024 * 1024, 'owners');
    renovateDoc = readJson(files.renovate, 2 * 1024 * 1024, 'renovate config');
    lockDoc = readJson(files.lock, 4096, 'image lock');
    checkGuardrails(renovateDoc);
    if (typeof lockDoc.image !== 'string' || typeof lockDoc.version !== 'string') {
      throw new Error('image lock needs image and version strings');
    }
  } catch (error) {
    return void fail(error.message);
  }

  // Standalone evidence gate: reviewers/CI confirm a receipt still matches
  // its exact inputs before treating a draft as qualified.
  if (args.ready) {
    let receipt;
    try {
      receipt = readJson(args.ready, 65536, 'receipt');
    } catch (error) {
      return void fail(`unreadable receipt: ${error.message}`);
    }
    const verdict = readyCheck(receipt, files, baseSha);
    process.stdout.write(JSON.stringify({receipt: args.ready, ...verdict}) + '\n');
    if (!verdict.passed) process.exitCode = 1;
    return;
  }

  const repository = args.repository;
  const base = args.base;
  if (typeof repository !== 'string' || !REPOSITORY_PATTERN.test(repository)) {
    return void fail('--repository must be owner/name');
  }
  if (typeof base !== 'string' || !BASE_PATTERN.test(base)) {
    return void fail('--base must be main or a cloudlab-maintenance-fixture branch');
  }
  const stagesDir = args.stages || here;
  const stateFile = args.state || path.join(process.cwd(), 'maintenance-state.json');
  const receiptsDir = args.receipts || path.join(process.cwd(), 'receipts');
  const proposeTimeout = args['propose-timeout-ms'] ? Number(args['propose-timeout-ms']) : PROPOSE_TIMEOUT_MS;
  if (!Number.isInteger(proposeTimeout) || proposeTimeout <= 0) return void fail('bad --propose-timeout-ms');
  let state;
  try {
    state = loadState(stateFile);
  } catch (error) {
    return void fail(error.message);
  }
  const bindings = Object.fromEntries(Object.entries(files).map(([key, file]) => [key, sha256File(file)]));
  const dryRun = args['dry-run'] === true || args['dry-run'] === 'true';
  let failed = false;
  for (const group of policy.maintenance.groups) {
    const resolved = resolveOwner(ownersDoc, group.owner);
    if (!resolved) {
      process.stdout.write(JSON.stringify({owner: group.owner, due: false,
        failed: true, reason: 'unknown owner; no proposal'}) + '\n');
      failed = true;
      continue;
    }
    const last = state.lastRun[group.owner] || 0;
    const due = now - last >= CADENCE_SECONDS[group.cadence];
    if (!due) {
      process.stdout.write(JSON.stringify({owner: group.owner, due: false,
        nextDueInSeconds: CADENCE_SECONDS[group.cadence] - (now - last)}) + '\n');
      continue;
    }
    const plan = ['qualify', 'propose', 'record'];
    if (dryRun) {
      process.stdout.write(JSON.stringify({owner: group.owner, due: true,
        stages: plan, repository, base, baseSha}) + '\n');
      continue;
    }
    const stages = [];
    let outcome = null;
    try {
      // The qualification runner binds its toolchain record to this group run;
      // qualify.cjs refuses any other role, and the candidate tree stays the
      // exact reviewed base until the writer proposes.
      fs.writeFileSync(TOOLCHAIN_FILE, JSON.stringify({role: 'candidate-runner',
        operation: crypto.randomBytes(16).toString('hex'), candidateTree: baseSha}),
        {mode: 0o600});
      const qualified = runQualify(stagesDir, lockDoc.image);
      stages.push({name: 'qualify', passed: qualified});
      if (!qualified) throw new Error('toolchain qualification failed');
      const request = {operation: crypto.randomBytes(16).toString('hex'),
        repository, base, ownerPaths: resolved.ownerPaths,
        dependencies: resolved.dependencies, expiresAt: now + 120};
      const result = runPropose(request, proposeTimeout);
      stages.push({name: 'propose', passed: result.passed});
      if (!result.passed) throw new Error('trusted writer reported failure');
      fs.mkdirSync(receiptsDir, {recursive: true});
      const receipt = {version: 1, operation: request.operation, repository, base,
        baseSha, headSha: result.headSha, owner: group.owner,
        ownerPaths: resolved.ownerPaths, dependencies: resolved.dependencies,
        toolchain: {image: lockDoc.image, version: lockDoc.version},
        bindings, stages, createdAt: now};
      const receiptFile = path.join(receiptsDir, `${request.operation}.json`);
      atomicJson(receiptFile, receipt);
      const verdict = readyCheck(receipt, files, baseSha);
      if (!verdict.passed) throw new Error(`fresh receipt rejected: ${verdict.reason}`);
      state.lastRun[group.owner] = now;
      atomicJson(stateFile, state);
      outcome = {owner: group.owner, due: true, stages, passed: true, receipt: receiptFile};
    } catch (error) {
      outcome = {owner: group.owner, due: true, stages, passed: false, reason: error.message};
      failed = true;
    }
    process.stdout.write(JSON.stringify(outcome) + '\n');
  }
  if (failed) process.exitCode = 1;
}

main();

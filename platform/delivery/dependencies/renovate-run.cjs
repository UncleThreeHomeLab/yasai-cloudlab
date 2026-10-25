// Token enters on stdin; neither a key nor candidate code enters this container.
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => {
  input += chunk;
  if (input.length > 16384) process.exit(2);
});
process.stdin.on('end', () => {
  let request;
  try {
    request = JSON.parse(input);
    if (Object.keys(request).sort().join(',') !== 'base,dependencies,expiresAt,operation,ownerPaths,repository,token' ||
        !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(request.repository) ||
        !/^(main|cloudlab-maintenance-fixture\/[a-z0-9-]{1,64})$/.test(request.base) ||
        !/^[a-f0-9]{32}$/.test(request.operation) ||
        !Number.isInteger(request.expiresAt) || request.expiresAt < Date.now() / 1000 ||
        request.expiresAt > Date.now() / 1000 + 120 ||
        typeof request.token !== 'string' || !request.token || /\s/.test(request.token)) {
      throw new Error('Invalid scope');
    }
    const owners = Object.values(JSON.parse(fs.readFileSync('/trusted/owners.json', 'utf8')).owners);
    const validPaths = new Set(owners.flatMap(owner => [...owner.sources, ...owner.companions]));
    const validDependencies = new Set(owners.flatMap(owner => owner.nativeDependencies));
    if (!Array.isArray(request.ownerPaths) || request.ownerPaths.length === 0 || request.ownerPaths.some(path => !validPaths.has(path)) ||
        !Array.isArray(request.dependencies) || request.dependencies.length === 0 || request.dependencies.some(name => !validDependencies.has(name))) {
      throw new Error('Invalid owner selection');
    }
    fs.writeFileSync('/tmp/operation.json', JSON.stringify({repository: request.repository, base: request.base,
      ownerPaths: request.ownerPaths, dependencies: request.dependencies}), {mode: 0o600});
    const log = fs.openSync('/tmp/renovate-private.log', 'w', 0o600);
    const result = spawnSync('/usr/local/renovate/node', ['/usr/local/renovate/dist/renovate.js'], {
      env: {PATH: process.env.PATH, HOME: '/tmp/home', RENOVATE_TOKEN: request.token,
            RENOVATE_BASE_DIR: '/tmp/renovate', RENOVATE_CONFIG_FILE: '/trusted/renovate.cjs',
            RENOVATE_USE_CLOUD_METADATA_SERVICES: 'false', LOG_FORMAT: 'json', LOG_LEVEL: 'debug'},
      stdio: ['ignore', log, log], timeout: 1800000
    });
    fs.closeSync(log);
    if (fs.statSync('/tmp/renovate-private.log').size > 32 * 1024 * 1024) throw new Error('Bounded log limit');
    const records = fs.readFileSync('/tmp/renovate-private.log', 'utf8').split('\n').flatMap(line => {
      try { return [JSON.parse(line)]; } catch { return []; }
    });
    const completed = records.some(row => row.repository === request.repository && row.msg === 'Repository finished' && row.result === 'done');
    const extracted = new Set();
    for (const row of records) {
      if (row.repository !== request.repository || row.baseBranch !== request.base || row.msg !== 'packageFiles with updates') continue;
      for (const packages of Object.values(row.config || {})) {
        if (!Array.isArray(packages)) continue;
        for (const file of packages) for (const dependency of file.deps || []) {
          const identity = dependency.packageName || dependency.depName;
          if (request.dependencies.includes(identity)) extracted.add(identity);
        }
      }
    }
    const passed = result.status === 0 && completed && extracted.size > 0 && !records.some(row => row.level >= 50);
    process.stdout.write(JSON.stringify({operation: request.operation, passed, extracted: extracted.size}) + '\n');
    process.exitCode = passed ? 0 : 1;
  } catch {
    process.stderr.write('Maintenance proposal failed; private diagnostics withheld\n');
    process.exitCode = 1;
  } finally {
    if (request) request.token = '';
    fs.rmSync('/tmp/operation.json', {force: true});
  }
});

// Bounded single-use handoff shared only with the trusted credential owner.
const fs = require('node:fs');
const {spawnSync} = require('node:child_process');
const deadline = Date.now() + 120000;
const poll = setInterval(() => {
  if (Date.now() > deadline) {
    clearInterval(poll);
    process.exitCode = 1;
  } else if (fs.existsSync('/handoff/request.json')) {
    clearInterval(poll);
    const input = fs.readFileSync('/handoff/request.json', 'utf8');
    if (input.length > 16384) {
      process.exitCode = 1;
      return;
    }
    const result = spawnSync('node', ['/trusted/renovate-run.cjs'], {
      input, env: {PATH: process.env.PATH}, encoding: 'utf8', timeout: 1810000,
      maxBuffer: 16384
    });
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
  }
}, 250);

# Native extraction fixture

Synthetic mini-repo mounted at `/fixture` for `extract.cjs` qualification.
Lock files and charts are copies of the reviewed real inputs (same relative
paths the custom managers target); `Dockerfile`, `package.json` and
`requirements.txt` coverage stays minimal and exact. `renovate.json` is a
deliberately hostile repository config: every escalation it attempts is
pinned under `force` in the trusted config, so extraction must retain the
trusted managers and groups despite it. Real maintenance runs ignore this
directory via `force.ignorePaths`; refresh the copies if a targeted real
file changes shape.

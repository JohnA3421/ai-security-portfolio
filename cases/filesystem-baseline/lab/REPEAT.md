# Repeat the first folder-boundary experiment

These instructions reproduce the completed source-level integration baseline using a fresh checkout and synthetic temporary folders. They require Git, Node.js 24 or later, npm, and network access to GitHub and the npm registry. The exact tested environment is in `../evidence/environment.json`.

## Prepare a fresh source snapshot

Run from a new working directory. Replace `/absolute/path/to/packet` below with the extracted starter packet directory.

```bash
git clone --filter=blob:none --no-checkout https://github.com/modelcontextprotocol/servers.git upstream
git -C upstream worktree add --detach ../baseline 82acf2aabf47bd462606a0d879e4849c26b2afae
cd baseline
git rev-parse HEAD
node --version
npm --version
```

Read the pinned project's `AGENTS.md`, `SECURITY.md`, and `CONTRIBUTING.md`. The experiment adds only a local test file; no source fix or external submission is part of it.

## Install the lockfile and run the upstream path suite

```bash
npm ci --ignore-scripts --no-audit --no-fund --fetch-timeout=20000 --fetch-retries=1
npm test -w src/filesystem -- __tests__/server-paths.test.ts --reporter=json --outputFile=upstream-paths.json
```

The output file is written relative to the filesystem workspace (`src/filesystem`). Absolute output paths also work, as the original command records show. Package install scripts are disabled. These focused tests run the source through the existing in-memory protocol harness and do not require a built binary.

## Place and run the custom experiment

```bash
cp /absolute/path/to/packet/lab/cvp-boundary.test.ts src/filesystem/__tests__/cvp-boundary.test.ts
npm test -w src/filesystem -- __tests__/cvp-boundary.test.ts --reporter=json --outputFile=pilot-boundary.json
npm run typecheck -w src/filesystem
git diff --stat
git status --short
```

The source test imports `./helpers.js`, so it must sit beside the upstream `helpers.ts`. Vitest resolves the TypeScript source as the upstream suite does. `git diff --stat` should show no tracked source changes; `git status --short` should list the added untracked test.

The original run observed **9 custom passes, 0 skips, 0 failures** and **40 upstream passes, 5 skips, 0 failures**. The five upstream cases require a case-insensitive filesystem. Different operating systems can produce different skip counts; record them accurately. The custom symlink case skips if the host cannot create a symlink, and passed on the original Linux host.

## What the result supports

The custom suite calls the real server through the SDK client. It asserts explicit access denial and checks disk state, including unchanged outside bytes, missing forbidden creations, and preserved move sources. Each test creates and removes a new temporary fixture tree.

A passing result shows that these selected expected behaviors held for this snapshot and environment. It is not an original discovery, a security certification, a complete platform test, or evidence of CVP admission. A failure is an observation to investigate before assigning a cause or severity.

# Reproduce this case (CVE-2025-53110)

A single command reproduces the before/after result in isolated local environments using only
synthetic fixtures. This reproduces published work by Elad Beber (Cymulate); it is calibration, not
an original discovery.

## Prerequisites

- Node.js 18 or later (tested on v24.14.1) and npm (tested on 11.11.0).
- Network access to the npm registry (to install the pinned server versions on first run).
- No special privileges. No symlinks are used, so this runs on Windows as-is.

## One command

From this directory (`cases/stage2-escaperoute/`):

```
node reproduce.mjs
```

It will:

1. Install the pinned server versions into isolated folders (idempotent; skipped if present):
   - `servers/affected/`  -> `@modelcontextprotocol/server-filesystem@2025.1.14`
   - `servers/fixed/`     -> `@modelcontextprotocol/server-filesystem@2025.7.1`
   - `servers/baseline/`  -> `@modelcontextprotocol/server-filesystem@2.0.1`
   - `harness/`           -> `@modelcontextprotocol/sdk@1.32.2`
2. Create fresh synthetic fixtures in a temp directory (an allowed `workspace`, an outside sibling
   `workspace_secret` that shares the name prefix, and an unrelated `far_outside` control).
3. Launch each server version over stdio with the same single allowed directory and issue the same
   requests through the same `read_file` tool.
4. Write raw evidence to `evidence/`, run the automated assertions, and write `evidence/MANIFEST.sha256`.

Exit code is 0 only if the experiment verdict and every assertion pass.

## Expected result

- **Affected `2025.1.14`:** reading `workspace_secret/secret.txt` returns the secret bytes
  (`CVP_SECRET_SIBLING_OUTSIDE_53110`) although only `workspace` was allowed — the bypass.
- **Fixed `2025.7.1`** and **baseline `2.0.1`:** the identical request returns
  `Access denied - path outside allowed directories`.
- Controls on every version: the inside read succeeds; a far-outside read (no shared prefix) is denied.

## Run the pieces separately (optional)

```
# install only
node -e "process.exit(0)"   # placeholder; installs happen inside reproduce.mjs

# experiment only (after installs)
node harness/run.mjs

# assertions only (after an experiment run)
node --test harness/assertions.test.mjs
```

## If results do not match

Record the discrepancy; do not adjust the evidence. Check, in order: the resolved server version
(`npm ls` in the server folder), the read tool the client selected (`read_tool_used` in
`evidence/raw/*.json`), the reported allow-list (`list_allowed_directories` in the same files), and
whether the fixtures were created as siblings rather than nested. The affected and fixed version
numbers must straddle the fix at `2025.7.1`.

## Environment note

Node's `fs.symlink` is blocked on this Windows host (EPERM) without Developer Mode or an elevated
shell. This case uses no symlinks, so it is unaffected. The companion symlink case (CVE-2025-53109)
requires Linux/WSL or Developer Mode and is deferred.

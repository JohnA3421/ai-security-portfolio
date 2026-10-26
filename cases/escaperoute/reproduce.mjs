// Single-command reproduction for CVE-2025-53110 (MCP filesystem allowed-directory bypass).
//
//   node reproduce.mjs
//
// It installs the pinned affected/fixed/baseline server versions and the client
// harness (if not already installed), runs the before/after experiment, runs the
// automated assertions, and writes an evidence manifest. Exit 0 only if every
// assertion passed. Prerequisites: Node 18+, npm, network access to the npm
// registry. Local, synthetic fixtures only; no external network target.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const NPM = process.platform === "win32" ? "npm.cmd" : "npm";

function sh(cmd, args, cwd) {
  const r = spawnSync(cmd, args, { cwd, stdio: "inherit", shell: process.platform === "win32" });
  if (r.status !== 0) {
    throw new Error(`Command failed (${r.status}): ${cmd} ${args.join(" ")} [cwd=${cwd}]`);
  }
}

function ensureInstalled(dir) {
  const abs = path.join(ROOT, dir);
  if (!fs.existsSync(path.join(abs, "node_modules"))) {
    console.log(`\n== installing dependencies in ${dir} ==`);
    sh(NPM, ["install", "--no-audit", "--no-fund", "--ignore-scripts"], abs);
  } else {
    console.log(`== ${dir}: dependencies already present, skipping install ==`);
  }
}

function sha256File(p) {
  return crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
}

function walk(dir, acc = []) {
  for (const name of fs.readdirSync(dir)) {
    const p = path.join(dir, name);
    const st = fs.statSync(p);
    if (st.isDirectory()) walk(p, acc);
    else acc.push(p);
  }
  return acc;
}

function writeManifest() {
  const targets = [
    "PLAN.md", "CASE-STUDY.md", "REPRODUCE.md", "reproduce.mjs",
    "harness/run.mjs", "harness/assertions.test.mjs", "harness/package.json",
    "servers/affected/package.json", "servers/fixed/package.json", "servers/baseline/package.json",
  ];
  const lines = [];
  for (const t of targets) {
    const p = path.join(ROOT, t);
    if (fs.existsSync(p)) lines.push(`${sha256File(p)}  ${t.replace(/\\/g, "/")}`);
  }
  const evDir = path.join(ROOT, "evidence");
  for (const p of walk(evDir)) {
    if (path.basename(p) === "MANIFEST.sha256") continue;
    const rel = path.relative(ROOT, p).replace(/\\/g, "/");
    lines.push(`${sha256File(p)}  ${rel}`);
  }
  lines.sort((a, b) => a.slice(66).localeCompare(b.slice(66)));
  fs.writeFileSync(path.join(evDir, "MANIFEST.sha256"), lines.join("\n") + "\n");
  console.log(`\n== wrote evidence/MANIFEST.sha256 (${lines.length} files) ==`);
}

// 1. Install isolated environments (idempotent).
for (const d of ["servers/affected", "servers/fixed", "servers/baseline", "harness"]) {
  ensureInstalled(d);
}

// 2. Run the experiment (produces evidence/). Non-zero exit if the verdict fails.
console.log("\n== running before/after experiment ==");
const exp = spawnSync(process.execPath, [path.join(ROOT, "harness", "run.mjs")], {
  stdio: "inherit",
});
const experimentOk = exp.status === 0;

// 3. Run automated assertions over the captured evidence.
console.log("\n== running automated assertions ==");
const asserts = spawnSync(
  process.execPath,
  ["--test", path.join(ROOT, "harness", "assertions.test.mjs")],
  { stdio: "inherit" },
);
const assertionsOk = asserts.status === 0;

// 4. Evidence manifest.
writeManifest();

const ok = experimentOk && assertionsOk;
console.log(`\n==== REPRODUCTION ${ok ? "PASSED" : "FAILED"} ====`);
console.log(`experiment exit=${exp.status}, assertions exit=${asserts.status}`);
console.log("Evidence: cases/stage2-escaperoute/evidence/");
process.exit(ok ? 0 : 1);

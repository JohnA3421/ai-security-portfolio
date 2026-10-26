// Demonstrate the filesystem server's allow-list through real client tool calls.
// Synthetic sibling fixtures and on-disk checks distinguish access enforcement
// from malformed requests or an error response that still changed a file.

import fs from "fs/promises";
import path from "path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallToolResult } from "@modelcontextprotocol/client";
import {
  call,
  connect,
  makeTempDir,
  quietStderr,
  textOf,
  type Connected,
} from "./helpers.js";

const INSIDE_MARKER = "CVP_ALLOWED_CONTENT_20261025";
const OUTSIDE_MARKER = "CVP_OUTSIDE_CONTENT_20261025";
const SIBLING_MARKER = "CVP_SIBLING_CONTENT_20261025";

let fixtureRoot: string | undefined;
let allowed: string;
let outside: string;
let sibling: string;
let connection: Connected | undefined;

async function invoke(
  name: string,
  args: Record<string, unknown>,
): Promise<CallToolResult> {
  if (!connection)
    throw new Error("The fixture did not establish a connection");
  return call(connection.client, name, args);
}

function assertAccessDenied(
  result: CallToolResult,
  forbiddenMarker?: string,
): void {
  expect(result.isError).toBe(true);
  expect(textOf(result)).toMatch(/^Access denied - /);
  if (forbiddenMarker !== undefined) {
    expect(JSON.stringify(result)).not.toContain(forbiddenMarker);
  }
}

function hostCannotCreateSymlinks(error: unknown): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    typeof error.code === "string" &&
    ["EPERM", "EACCES", "ENOSYS", "ENOTSUP"].includes(error.code)
  );
}

beforeEach(async () => {
  quietStderr();
  connection = undefined;
  fixtureRoot = await makeTempDir("cvp-fs-boundary-");
  allowed = path.join(fixtureRoot, "allowed");
  outside = path.join(fixtureRoot, "outside");
  sibling = path.join(fixtureRoot, "allowed-sibling");
  await fs.mkdir(allowed);
  await fs.mkdir(outside);
  await fs.mkdir(sibling);
  await fs.writeFile(path.join(allowed, "marker.txt"), INSIDE_MARKER);
  await fs.writeFile(path.join(outside, "marker.txt"), OUTSIDE_MARKER);
  await fs.writeFile(path.join(sibling, "marker.txt"), SIBLING_MARKER);
  connection = await connect([allowed]);
});

afterEach(async () => {
  try {
    await connection?.close();
  } finally {
    connection = undefined;
    try {
      if (fixtureRoot !== undefined) {
        await fs.rm(fixtureRoot, { recursive: true, force: true });
      }
    } finally {
      fixtureRoot = undefined;
      vi.restoreAllMocks();
    }
  }
});

describe("CVP pilot: configured folder boundary", () => {
  it("reads a marker inside the allowed directory", async () => {
    const result = await invoke("read_text_file", {
      path: path.join(allowed, "marker.txt"),
    });
    expect(result.isError).not.toBe(true);
    expect(textOf(result)).toBe(INSIDE_MARKER);
  });

  it("writes inside the allowed directory and changes the actual file", async () => {
    const destination = path.join(allowed, "created-inside.txt");
    const content = "CVP_INTENDED_WRITE_20261025";
    const result = await invoke("write_file", { path: destination, content });
    expect(result.isError).not.toBe(true);
    expect(await fs.readFile(destination, "utf8")).toBe(content);
  });

  it("denies an absolute outside read without returning the outside marker", async () => {
    const result = await invoke("read_text_file", {
      path: path.join(outside, "marker.txt"),
    });
    assertAccessDenied(result, OUTSIDE_MARKER);
  });

  it("denies a literal ../ traversal read without returning the outside marker", async () => {
    // Concatenation preserves ../ in the request sent over the transport.
    const requestedPath = `${allowed}${path.sep}..${path.sep}outside${path.sep}marker.txt`;
    expect(requestedPath).toContain(`${path.sep}..${path.sep}`);
    const result = await invoke("read_text_file", { path: requestedPath });
    assertAccessDenied(result, OUTSIDE_MARKER);
  });

  it("denies a sibling sharing the allowed directory's prefix", async () => {
    const result = await invoke("read_text_file", {
      path: path.join(sibling, "marker.txt"),
    });
    assertAccessDenied(result, SIBLING_MARKER);
  });

  it("denies a symlink inside allowed that points to an outside file", async (context) => {
    const link = path.join(allowed, "outside-link.txt");
    try {
      await fs.symlink(path.join(outside, "marker.txt"), link, "file");
    } catch (error) {
      if (hostCannotCreateSymlinks(error)) {
        console.info(
          "SKIPPED symlink boundary: this host cannot create symlinks",
        );
        context.skip();
        return;
      }
      throw error;
    }
    const result = await invoke("read_text_file", { path: link });
    assertAccessDenied(result, OUTSIDE_MARKER);
  });

  it("denies an outside overwrite and leaves the original bytes unchanged", async () => {
    const target = path.join(outside, "marker.txt");
    const originalBytes = await fs.readFile(target);
    const result = await invoke("write_file", {
      path: target,
      content: "CVP_FORBIDDEN_OVERWRITE_20261025",
    });
    assertAccessDenied(result);
    expect(await fs.readFile(target)).toEqual(originalBytes);
  });

  it("denies outside file creation and leaves no new file", async () => {
    const target = path.join(outside, "created-outside.txt");
    const result = await invoke("write_file", {
      path: target,
      content: "CVP_FORBIDDEN_CREATION_20261025",
    });
    assertAccessDenied(result);
    await expect(fs.stat(target)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("denies a move outside and preserves the source without creating the destination", async () => {
    const source = path.join(allowed, "marker.txt");
    const destination = path.join(outside, "moved-outside.txt");
    const originalBytes = await fs.readFile(source);
    const result = await invoke("move_file", { source, destination });
    assertAccessDenied(result);
    expect(await fs.readFile(source)).toEqual(originalBytes);
    await expect(fs.stat(destination)).rejects.toMatchObject({
      code: "ENOENT",
    });
  });
});

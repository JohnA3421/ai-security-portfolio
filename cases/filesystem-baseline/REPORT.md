# Filesystem boundary baseline

**Author:** John Austin, with AI assistance. **Recorded:** October 26, 2026.

Nine custom checks exercised selected expected folder-access behavior in the official MCP
filesystem server using real client tool calls and synthetic fixtures. All nine passed. The
upstream path suite passed 40 checks and skipped five platform-specific cases; typechecking passed.
No new vulnerability was observed.

Tested source revision: `82acf2aabf47bd462606a0d879e4849c26b2afae`; filesystem package `2.0.1`;
Linux, Node 24.22.1. See [environment](evidence/environment.json), [summary](evidence/summary.json),
[custom results](evidence/pilot-boundary.json), [upstream results](evidence/upstream-paths.json),
and [repeat instructions](lab/REPEAT.md).

These tests support only the selected operations and environment. Packaged stdio, other operating
systems, every filesystem tool, changing roots, and concurrent races were not established by this
baseline. Agent review occurred inside the author's workflow and is not third-party verification.

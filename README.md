# AI tool security research — John Austin

I direct AI-assisted defensive research into permission enforcement in AI tools and connectors.
This portfolio presents two completed, bounded experiments, with recorded results and reproduction
instructions. AI agents performed much of the implementation and evidence review; I define the
research scope and review the conclusions with their assistance.

## Start here

- [Security advisory and reproduced mitigation: CVE-2025-53110](advisories/CVE-2025-53110-reproduction.md).
- [Filesystem boundary baseline](cases/filesystem-baseline/REPORT.md): nine selected expected-behavior checks.
- [Methods, contribution, and evidence limits](METHODS.md).
- [Public evidence provenance](PROVENANCE.json) and [file checksums](SHA256SUMS).

## What was observed

| Case | Observation | Interpretation |
|---|---|---|
| Filesystem baseline | 9 custom checks passed; upstream suite 40 passed and 5 skipped; typecheck passed | Expected behavior on the tested Linux snapshot; no new vulnerability |
| CVE-2025-53110 reproduction | The affected version allowed the synthetic outside-sibling read; fixed and comparison versions denied it; both controls held | Reproduction of prior published work; no original-discovery claim |

The original discoverer of CVE-2025-53110 is **Elad Beber of Cymulate**. John Austin is the author
of this reproduction advisory, not the discoverer or credited reporter of that CVE.

## Reproduce the published issue

With Node.js 18+ and npm, from a fresh working copy:

```sh
cd cases/escaperoute
node reproduce.mjs
```

The command installs pinned npm versions and performs a local comparison using synthetic fixtures.
It writes fresh evidence in that working copy. [Prerequisites and expected results](cases/escaperoute/REPRODUCE.md).
The original successful run and a fresh author-side verification run are recorded in the public evidence.
No third party has independently reproduced this portfolio.

The [baseline instructions](cases/filesystem-baseline/lab/REPEAT.md) describe a separate source-level
Linux test. They are not a claim that every supported operating system or every tool was tested.

## Publication scope

This repository contains only work about expected behavior and an already-public, fixed vulnerability.
Unpublished third-party disclosures, private correspondence, and account-security details are excluded.
Observed results were recorded on October 26, 2026. Publication does not imply vendor endorsement,
a new CVE credit, an accepted new finding, or membership in any verification program.

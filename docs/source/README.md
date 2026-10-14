# Source material and verification status

Reviewed inputs:

- User-supplied `chat_handoff_full_transcript.md`, 71,526 bytes, ending at Turn 18.
  Latest explicit technology decisions are in Turns 15–17; assistant proposals
  and earlier discussion are not treated as finalized requirements.
  SHA-256: `8a4d7c77c61be434c45dbbab4c305f199ca1d0974a37bea6e3c9a9774074626c`.
- Shepherd main at commit `03c20ced6e995961eefac841188e1ab90b4f4f59`: README,
  SRS, patent implementation map, networking spec/package/relay, relevant issues.
- Public Shepherd V1 project #5: roadmapping/planning/lane views and open mesh
  work, inspected via public HTML because API credentials lack `read:project`.
- Tailcat upstream `go.mod`: Go 1.27.1 requirement at inspection time.

The user's browser was unavailable: T3 preview status and open both reported
that no desktop automation host was connected. Repository/project inspection
used GitHub/API/public web content instead.

The supplied PDF is available at `/home/radhey/Downloads/patent.pdf` (31
pages, 595,967 bytes). Its SHA-256 digest is
`f06a9046a10b76495176303c228cdcfe8a0bbe560efe564782055908f8a0a771`.
[`patent-map.md`](patent-map.md) indexes its claims, paragraphs, and figures
with PDF and printed-page references.

The supplied PDF is primary for patent-specific text, labels, and figure
availability. The handoff transcript, earlier maps, and planning notes are
secondary context. Project requirements and decisions govern implementation
scope. Provenance and page indexing are complete; claim-to-scope reconciliation
remains pending in [issue #72](https://github.com/i-got-this-faa/device-audit/issues/72).
The inventory does not determine claim coverage.

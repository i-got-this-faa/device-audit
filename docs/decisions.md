# Decisions retained from the handoff

The user explicitly requested a new organization repository and selected reuse
of Shepherd networking. The attached `chat_handoff_full_transcript.md` ends with
Turns 15–17 describing the current direction. Earlier security and fleet-manager
discussion can drift and does not automatically become product scope.

| Decision | Evidence | Treatment |
| --- | --- | --- |
| New repository under i-got-this-faa | Current user request, handoff 15–17 | Dedicated `device-audit`; Shepherd remains separate |
| Go controller | Handoff 15/17 | Selected |
| Go endpoint agent | Handoff 17 | Selected |
| Tailcat / userspace WireGuard / DERP | Current request, handoff 15/17, Shepherd spec 14 | Preserve design and package boundary; adapter absent upstream |
| Bespoke prediction model, no Jev | Explicit user statement in handoff 17 | Selected; architecture and dataset open |
| Local training + central aggregation | Handoff 15–17 patent interpretation | Core product capability, exact PDF references pending |
| Smart contracts + cryptographic verification | Explicit user statement in handoff 17 | Selected direction; chain and contract implementation open |
| Python + PyTorch | Assistant marked proposed in handoff 17 | Python interfaces included; no PyTorch dependency or model architecture selected |
| PostgreSQL | Marked proposed in handoff | Initial schema candidate only; no runtime DB binding |
| Windows-first | Marked proposed in handoff 15 | First collector target in backlog; fixture sender cross-builds |
| Frontend | Explicitly not finalized | Reserve dashboard surface; no framework selected |
| LLM explanations | Optional in handoff | Future optional component; prediction and aggregation do not depend on it |

Scaffold choices made here: private repository by default, stdlib-only local
demo, Go 1.27.1 aligned with Shepherd/Tailcat, an ephemeral bounded sample store,
strict versioned inputs, and explicit errors for unavailable mesh transport.
These choices do not settle production hosting, tenancy, identity, model
runtime, chain, frontend or collector cadence.

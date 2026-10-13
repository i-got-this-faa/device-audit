# Smart-contract audit verification

Smart contracts are an explicit user decision in the handoff. The chain,
execution environment, account permissions, governance and finality rules were
not selected. No Solidity/EVM or other platform is assumed by the scaffold.
`packages/audit.Anchorer` is the application-facing boundary.

Initial contract requirements:

- Register authorized audit writers and support revocation/rotation.
- Anchor a canonical, domain-separated evidence/report commitment with an
  opaque audit ID and policy version. Define encoding before hashing across
  Go/Python/contract runtimes.
- Reject unauthorized submissions and replay/overwrite of an existing ID.
- Emit a verifiable receipt and expose the commitment for later verification.
- Distinguish submitted transactions from finalized evidence; handle reorgs
  or the selected platform's equivalent.
- Keep logs, serial numbers, hostnames and sensitive model artifacts off chain.

Test authorization, immutable commitments, replay, rotation, finality and
off-chain digest verification before deploying a contract. Do not infer log
truth from a hash, signature, contract transaction, or model output. No real
chain account, signing key, deployment or transaction is created by the scaffold.

# Smart-contract audit verification

Smart contracts are an explicit user decision in the handoff. The chain,
execution environment, account permissions, governance and finality rules were
not selected. No Solidity/EVM or other platform is assumed by the scaffold.
`packages/audit.Anchorer` is the application-facing boundary.

Initial contract requirements:

- Register authorized audit writers and support revocation/rotation.
- Anchor a canonical, domain-separated evidence/report commitment with an
  random opaque audit ID. CT09 #79 defines the
  [versioned commitment encoding](../packages/contracts/audit-v1.md); policy
  version and signed manifest metadata remain off-chain. Go/Python fixtures
  check this format; a future chain runtime still needs interoperability tests.
- Reject unauthorized submissions and replay/overwrite of an existing ID.
- Emit a verifiable receipt and expose the commitment for later verification.
- Distinguish submitted transactions from finalized evidence; handle reorgs
  or the selected platform's equivalent.
- Keep logs, serial numbers, hostnames and sensitive model artifacts off chain.

Test authorization, immutable commitments, replay, rotation, finality and
off-chain digest verification before deploying a contract. Do not infer log
truth from a hash, signature, contract transaction, or model output. No real
chain account, signing key, deployment or transaction is created by the scaffold.

CT09 #79 also defines off-chain pending/finalized/reverted receipt observations
and evidence-verification states. The legacy `packages/audit.Anchorer` interface
is unchanged and has no implementation. A consumer must adopt the versioned
contracts explicitly; a receipt boolean or parsed fixture cannot establish
finality. Chain selection and real authorization/reorganization tests remain open.

# Release chain, permissions and finality, CHAIN01 #47

Decision dated 13 November 2026. Select **Base Mainnet, EVM chain ID 8453**
for V1 public audit commitments. Base Sepolia, chain ID 84532, is the separate
integration environment. Local EVM tests and testnet deployments never satisfy
release-network evidence. This selects a design; no contract, wallet, RPC
subscription, signing credential or transaction is provisioned here.

## Why this chain

The workload writes small, asynchronous, blinded commitments. It does not need
payment settlement or subsecond audit finality. Base permits EVM tooling and
L1-derived finality while moving transaction execution off Ethereum L1.
Expected lower write costs are an engineering inference from rollup execution
and shared L1 data publication, not a measured deployment quote. Direct Ethereum
Mainnet would simplify the settlement trust model but pay L1 execution fees for
each write. A private chain would add validator operation and administrator
trust while weakening independent public verification. Neither is selected.

Accept Base sequencer availability/censorship risk, batch publication delay,
rollup derivation/protocol and upgrade-governance risk, RPC correctness and
Ethereum consensus risk. Do not describe this as trustless endpoint observation.
An independently operated verifying Base node with an authenticated Ethereum
execution/consensus source is the release verifier. A separately operated RPC
is a consistency cross-check, not a replacement for verification. Disagreement
blocks finality and submission. An unavailable verifier does not permit a
fallback to unverified public RPC responses.

Base's [derivation specification](https://docs.base.org/specifications/base-protocol/consensus/derivation)
defines finalized L2 blocks from finalized L1 inputs. Its withdrawal-output
challenge window is a different finality notion. This system anchors on L2 and
does not bridge or withdraw funds. Ethereum finality relies on its
[stake-weighted checkpoint consensus](https://ethereum.org/developers/docs/consensus-mechanisms/pos/).
Chain IDs are listed in Base's [RPC reference](https://docs.base.org/base-chain/api-reference/ethereum-json-rpc-api/eth_chainId).

## Writer and administrator permissions

- Deploy a non-upgradeable commitment registry per organization deployment.
  No proxy, delegatecall, arbitrary execution, raw-log storage or overwrite API.
  Its only audit data is CT09's version plus random opaque 32-byte commitment
  ID and blinded 32-byte digest. Transaction sender/time remain publicly visible;
  opaque payloads do not promise anonymity.
- Authorize a dedicated chain writer that can insert previously unused IDs.
  Repeated ID submissions fail, including the same digest. On uncertain replies,
  query existing state before considering another transaction. Another digest
  for that ID is always a conflict. The writer cannot grant roles, change
  administration, alter commitments or withdraw contract funds.
- The administrator is a 2-of-3 multisig with independently held hardware-backed
  owner keys. It may grant/revoke writers and initiate a two-step administrator
  transfer; the new multisig must accept. Ownership is not the routine writer or
  the deployer's personal account. The deployer relinquishes privileges after
  verified handover. No permanent deployer bypass is allowed.
- Writer private material stays in a dedicated non-exportable secp256k1 signing
  service with authenticated transaction-only access. It is separate from device
  Ed25519/X25519 keys, controller audit signing, mesh PSKs, OIDC and database
  credentials. Unavailable signing fails closed; no plaintext file fallback.
  The controller supplies only an approved registry call and configured chain ID,
  recipient, nonce and fee bounds. Signer deployment/custody tests remain a
  release prerequisite, not a capability of the existing scaffold.
- Revoke a compromised writer immediately through the multisig, stop the worker,
  wait for finalized revocation, reconcile pending transactions, then authorize
  and verify a new writer. Receipt history records which writer was authorized
  at the historical write; revocation does not erase earlier commitments. A
  historical anchor does not prove that a compromised writer's data is true.
  No automatic remediation or automated administrator signing is introduced.

## Deployment and address strategy

`release-policy.json` records the chosen policy and an intentionally disabled
deployment descriptor. It is a decision/configuration template, not a running
adapter. Implementers must reject incomplete descriptors. Do not replace absent
addresses with the zero address, sample credentials or a testnet deployment.

A release descriptor must bind policy/adapter version, environment, chain ID,
registry address, deployed runtime-code Keccak-256, deployment transaction and
block hash, administrator multisig, authorized writer and trusted RPC/verifier
configuration. Include multisig implementation/code and threshold/owner custody
verification in deployment evidence. No addresses or RPC URLs come from audit
manifests, device requests or chain receipt reference strings. Never put an API
credential into the descriptor committed to source control.

Contract implementation uses a reproducible compiler and reviewed artifact;
pin constructor inputs and runtime code. Verify chain ID, code hash, registry
interface and roles against trusted state at startup and every receipt refresh.
Use historical authorization at the transaction block for old receipts. A new
registry, bytecode, administrator or adapter policy requires an explicit reviewed
deployment revision, preserving the old descriptor and receipts. Testnet and
mainnet descriptors have distinct adapter IDs; no automatic environment switch.

## Confirmation and finality algorithm

The adapter must perform all of these checks, without a wall-clock shortcut:

1. Verify the configured chain/deployment identity and retrieve the transaction
   receipt. Confirm successful execution, the intended registry call, writer
   authorization at inclusion, and exact CT09 ID/digest in the registry event
   and state. A transaction hash or block count alone is insufficient.
2. Compare the inclusion block's hash to the canonical block at that height.
   Inclusion, preconfirmation, `latest` and `safe` are all `pending`.
3. Query `eth_getBlockByNumber("finalized", false)` from the trusted verifying
   node and cross-check independently. The inclusion block must be at or below
   that finalized head on the same verified canonical chain. Unsupported tags,
   missing history, stalled finality, inconsistent sources or failed checks
   cannot establish finality. No fixed number of L2 confirmations substitutes.
4. Only after those checks, append a CT09 `finalized` receipt with its local
   observation/finality-verification time. Do not invent a protocol finality
   timestamp from the transaction's block time. Recheck on verification and
   refresh; preserve every prior receipt observation.

The [Base block RPC](https://docs.base.org/base-chain/api-reference/ethereum-json-rpc-api/eth_getBlockByNumber)
supports tagged block lookup. Finality latency is variable; a monitoring timeout
is an operational alert, never a finality rule or automatic evidence rejection.

## Revert, retry and unavailable-chain policy

| Observation | Current CT09 result | Required action |
|---|---|---|
| Not submitted, signing/RPC outage, insufficient funds or fee budget exceeded | Anchor `unverified`; no fabricated transaction receipt | Keep signed manifest/commitment durably off-chain, expose pending delivery, alert and retry later |
| Submitted with unknown result, or canonical inclusion above finalized head | `pending`, no finality time | Reconcile by stored signed transaction hash, sender nonce and ID/digest before retry; persist the signed transaction and nonce before broadcast |
| Successful canonical inclusion at or below finalized head, with every verification check satisfied | `finalized` with verified observation time | Append the receipt only after the confirmation/finality algorithm above passes |
| Mined transaction with failed execution | `reverted`, `transaction_failed` | Preserve failure; review cause before resubmitting the same commitment with a new transaction reference |
| Prior inclusion is no longer canonical | `reverted`, `reorganized` | Clear current finality, preserve old observations and reconcile before resubmission |
| Reconciliation establishes a prior write was invalidated and trusted canonical state proves its commitment absent | `reverted`, `commitment_absent` | Preserve the observation; retry only the original immutable ID/digest after nonce reconciliation. Absence before inclusion stays `pending` while the transaction can still be included |
| RPC/history missing, disagreement, wrong chain/code/writer or unverified deployment | Anchor `unverified` on refresh; preserve the last observation as history | Stop submission/finality claims and alert; absence of a response is not proof of a revert |
| ID exists with another digest | Verification conflict | Stop, alert and retain both off-chain records; never overwrite or silently assign a new ID |

On chain unavailability, off-chain collection/storage may continue under its
existing rules, but the UI/export must say anchoring is unverified or pending.
It must not claim blockchain verification. Queue saturation returns an explicit
unavailable result before accepting more anchoring work; no silent drops. Durable
queue implementation and its retention/backpressure bounds belong to the adapter
tasks. Evidence expiry/missing data remain independent from chain state.

A previously finalized observation becoming noncanonical is a severe verifier/
consensus incident. Suspend the writer, append the reverted observation and
require operator reconciliation. Never automatically repair it with a different
manifest or nonce.

## Operational cost and limits

Use ETH for gas on Base. Estimate the actual reviewed registry call before
signing. The maximum cost includes L2 execution, L1 data publication and any
active operator fee; a quote that includes only `gasPrice * gas` is incomplete.
Base's [fee documentation](https://docs.base.org/specifications/transactions/network-fees)
defines these components and the gas-price oracle methods. Use a conservative
upper bound for the serialized transaction, not a stale token-transfer quote.

Initial engineering spending ceilings are 0.0001 ETH per transaction and
0.001 ETH per rolling 24 hours per deployment. These are chosen limits, not
current network prices, an ETH purchase recommendation or spending authorization.
Track reserved worst-case fees for pending transactions plus actual settled fees;
concurrent writers/replacements cannot bypass the daily ceiling. Unused
reservations are released only after nonce/receipt reconciliation. If each write
hits the per-transaction ceiling, at most ten fit that daily budget. Do not change
the CT09 commitment format to combine manifests merely to meet the budget.

Before enabling mainnet, measure gas for deployment, grant/revoke and actual
commitment insertion using the reviewed artifact; record current L1/L2/operator
fee inputs, estimation time, signed byte size and estimated/actual ETH totals.
Record signer/verifying-node hosting and multisig hardware/custody cost separately.
The current repository has no bytecode or live quote, so no dollar cost or measured
mainnet cost is claimed. Funding, provider contracts and deployment require a
separate authorized operation. An operator may lower these ceilings; raising them
requires a reviewed policy change.

## Acceptance handoff

#47 supplies chain selection, role/custody design, finality/revert/outage policy,
cost rationale and the deployment configuration strategy. Contract implementation,
signer service, durable worker, RPC verification and measured deployment remain
follow-on tasks. Before release, attach local/testnet authorization, replay,
rotation, reorg, outage and fee-cap evidence, then separately verify the selected
mainnet deployment. A local fixture or this policy file cannot establish any of
those runtime facts. Reviewed PR/merge remains an issue-completion gate.

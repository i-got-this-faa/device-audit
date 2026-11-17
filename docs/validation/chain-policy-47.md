# CHAIN01 descriptor validation, 16 November 2026

Issue #47. This records local checks of the Base Mainnet policy already selected
on 13 November 2026 in [the release policy](../../contracts/release-policy.md).
The committed descriptor stays disabled. No address, credential, RPC endpoint,
or contract bytecode was added.

## What was checked

- `contracts/release-policy.json` parses as disabled Base Mainnet, chain ID 8453,
  with a 2-of-3 administrator, the selected fee ceilings, and no deployment fields.
- `contracts/fixtures/policy/v1-vectors.json` separates that release network from
  disabled Base Sepolia and local EVM descriptors. Incomplete enabled descriptors,
  zero addresses, null `enabled`, local chain IDs 1, 8453, and 84532, device
  identifiers, hostnames, and raw logs are rejected. Parse rejects raised fee
  ceilings; the JSON Schema wei pattern does not. Reference checks reject listed
  key and device-identity words and do not prove a reference contains no secret.
- `contracts/fixtures/policy/observations.json` matches the confirmation, revert,
  and outage rules. One rule claims finality. Outage and source disagreement do
  not fabricate a revert. A lost canonical inclusion clears current finality.
- Python Draft 2020-12 validation uses `contracts/release-policy.schema.json`
  and the same vectors. Schema success is not deployment evidence.
  `ReleaseDeploymentObserved` remains false for every accepted descriptor,
  including the synthetic enabled mainnet shape.

## Commands

Go 1.27.1 and Python 3.12 with `models/test-requirements.txt` (jsonschema 4.25.1)
installed in a temporary directory:

```sh
make PYTHON=/tmp/bin/python-policy check cross-build
git diff --check
```

`/tmp/bin/python-policy` runs system Python 3.12 with that temporary dependency
directory on `PYTHONPATH`. The host Python without those packages cannot import
`jsonschema`.

## Results

Passed on 16 November 2026:

- `go vet ./...`
- `go test -race ./...`, including `contracts/policy`
- 34 Python tests under `models/tests`, including `test_chain_policy`
- controller fixture scenarios
- `go fmt` clean
- Windows amd64 and Darwin arm64 endpoint cross-builds
- `git diff --check`

## Untested flows

No Base or Ethereum RPC was contacted. No contract was compiled or deployed.
No transaction was signed or broadcast. Gas for deployment, grant/revoke, and
commitment insertion was not measured. Signer-service, hardware-multisig, and
verifying-node custody were not exercised. `packages/audit.Anchorer` has no
implementation, so authorization, replay, reorg, and fee settlement were not
run against a chain. A passing descriptor test does not prove inclusion or
finality.

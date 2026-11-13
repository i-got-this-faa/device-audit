# Endpoint identity storage, SEC02 #23

The endpoint can explicitly enroll separate Ed25519 application-signing and
X25519 network identities through the existing bootstrap v1 protocol. It saves
keys before sending proofs, pins their deployment/device scope, and saves a
public admission receipt only after a matching HTTP 201 response. Normal status
reads never provision keys. The default executable mode still sends unsigned
fixture telemetry over loopback. Enrollment does not enable production mesh or
authenticated telemetry delivery.

## Enroll and inspect

Obtain a one-use bootstrap-token.v1 JSON document through the authorized
[administrator enrollment flow](../../infra/enrollment/README.md). Deliver its
bytes directly on standard input through an approved private channel. Do not
put its token in command arguments, environment variables, terminal history or
logs. The examples below contain no credential.

```sh
endpoint-agent --enroll --state-dir /private/parent/endpoint-identity \
  --enrollment-origin https://controller.example.org --ca-file /path/to/ca.pem
endpoint-agent --identity-status --state-dir /private/parent/endpoint-identity
```

`--ca-file` is optional when the controller uses the system trust store.
Specifying it replaces the trust roots for enrollment. There is no insecure TLS
option, redirect following, proxy environment lookup or plaintext enrollment.
Only a bare HTTPS origin is accepted. Treat selecting the correct origin and
CA as operator authorization. Responses and errors never echo server bodies,
bootstrap credentials, private keys or decrypted network proofs. Status prints
only the public receipt. It proves local retained admission, not current remote
authorization, revocation status or connectivity.

The parent directory must already exist and be protected against replacement
by unrelated users. The endpoint creates only its own final directory. The
state directory is exclusive to this installation and process account. Files
are size-bounded, regular, single-link files. Reparse points/symlinks for the
identity directory or state files are rejected. An OS lock prevents concurrent
operations and is released when the process exits. `identity.lock` persists as
an empty file; never delete it while any endpoint operation is running.

## Windows boundary

Windows stores the key bundle through user-scoped DPAPI with UI disabled.
The directory has a protected DACL granting full access to SYSTEM and the
enabled per-service SID. OWNER RIGHTS grants only READ_CONTROL to suppress the
owner's implicit WRITE_DAC, so another LocalService process does not obtain
access solely by sharing the owner SID. Files inherit this DACL. Each open
checks the owner, exact allowed ACL and file/link type. Unexpected grants or
unreadable ACLs fail without repairing permissions or replacing keys.

LocalService without an enabled per-service SID fails. Interactive development
uses the process user SID instead. Run provisioning and later reads under the
same account and service token. Interactive provisioning does not qualify or
initialize the LocalService installation. Service registration, SID activation,
private parent provisioning and running this operation under the service token
belong to installation/service work #26/#57/#64. Administrators and SYSTEM can
override filesystem protection; this does not defend against a compromised
administrator, the endpoint process or its authorized principal. DPAPI backup,
profile loss and account migration require an explicit recovery design.

## Unix development boundary

Linux and Darwin use current-owner directory mode 0700 and file mode 0600,
reject hard links, and flush files plus the directory. A SHA-256 checksum detects
accidental key-file corruption. This is access-controlled plaintext development
storage, not a keychain, TPM or encryption-at-rest claim. These platforms remain
outside the selected V1 endpoint support matrix. Windows cross-compilation does
not qualify DPAPI, DACL inheritance, disk durability or LocalService execution.

## Failure and recovery

Keys, pending scope and admission receipt are created exclusively and never
overwritten. Missing keys next to scope/receipt, partial creation, corruption,
bad permissions, mismatched scope, invalid challenge, wrong-key proofs and
mismatched receipts fail closed. A failed initial write can leave a partial file;
this deliberately blocks retries rather than replacing identity. Restart reuses
the same key bundle and receipt. A pending enrollment may retry its existing
tuple; an admitted installation returns its saved receipt without redemption.

A dropped admission response is uncertain. A consumed-token rejection cannot
establish whether a previous request committed. Keep the entire state directory,
stop retrying, and reconcile with an authorized operator. Do not delete keys,
reset permissions or issue a replacement identity as an automatic recovery step.
Receipt reconciliation, key rotation, revocation, backup/restore and deletion are
separate work. Local rollback of the public receipt is not remote de-admission.
The receipt is not a signed acknowledgement or blockchain evidence. No endpoint
identifier, raw telemetry or private material is written on-chain.

## Signed evidence and sequence allocation, SEC07 #87

An admitted installation signs CT04 `device-audit.evidence.v1` envelopes:

```sh
endpoint-agent --sign-evidence --state-dir /private/parent/endpoint-identity < telemetry-v2.json
```

Standard input is one exact `device-audit.telemetry.v2` payload (at most
262144 bytes) whose `device_id` matches the admission receipt. The payload is
validated before a sequence is consumed and is hashed as supplied, never
re-encoded. The envelope binds the receipt's deployment, device and signing key
ID, a one-hour submission validity window and a freshly reserved sequence. The
signer verifies its own signature before printing the envelope. Errors are
generic and never echo payload content or key material.

`sequence.state` holds the reservation high-water mark beside the receipt,
bound to the admitted scope and protected by a SHA-256 checksum. Enrollment
creates it at mark 1 before saving the receipt. Each signature first writes the
next mark to a private temporary file, flushes it, renames it over the state and
flushes the result (plus the directory on Unix) before signing. A crash before
the rename leaves the old mark, whose next value was never signed. A crash after
it leaves a gap, which v1 permits. Missing, corrupt, out-of-scope, below-receipt
or exhausted state fails closed; the endpoint never restarts from the receipt.
Admitted installations from before this change lack `sequence.state` and must be
reconciled by an operator rather than reset.

This produces and signs evidence only. Transport, spooling the signed request
for retry, acknowledgement handling and controller ingestion remain #24/#25/#26.
Restoring an older state directory can reopen used local sequences; the
controller's durable mark still rejects them as `replay`. The signature proves
integrity and key possession, not sensor truth.

## Verification

```sh
go test -race -count=1 ./apps/endpoint-agent
make check cross-build
```

The package tests exercise real TLS, canonical proofs, disk storage and a fresh
process reading the same identity. The TLS peer is explicitly a protocol fixture.
With `TEST_DATABASE_URL` set, `TestEndpointEnrollmentPostgres` additionally uses
the real controller enrollment handlers and PostgreSQL admission transaction.
`make database-check` includes this integration and creates a disposable database.
Windows-only tests exercise real DPAPI, overly broad and deny-read DACLs when run
on Windows. Existing Windows CI runs the package through `tools/check-windows.ps1`.
That interactive CI account does not prove the selected physical Windows laptop
or LocalService/per-service token. See the [completion evidence](../../docs/validation/endpoint-keys-23.md).

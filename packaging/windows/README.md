# Windows endpoint package

The package targets the selected Windows 11 25H2 x64 endpoint. Hosted Windows
Server 2025 runs the clean-install test. The
[release platform matrix](../../docs/roadmap/release-scope.md#endpoint-platform-matrix)
governs support claims. An operator runs the installer once from an elevated,
native x64 PowerShell 7.4+ session. The service and its inference worker run
from the same native Go executable. Collection needs no Go, Python, model
server or third-party driver installation on the endpoint.

## Build and sign

Use an exact reviewed Git commit, Python 3.12+ and a Go launcher that can run
the patch version pinned in that commit's `go.mod`. The builder exports the
tracked source directly from Git. The package is reproducible for the same
commit and the same optional model files. Run a second build to a new directory
and compare the ZIP and provenance JSON before signing.

```sh
python3 packaging/windows/build.py --revision <40-character-commit> --output dist
```

To bundle an approved model, pass `--model-dir <directory>` containing
`manifest.json`, `artifact.json`, `publisher.pem` and `evaluation.json`.
The CT10 manifest must be signed for the compiled inference runtime. The
evaluation must pass the endpoint policy for that exact artifact. The
installer checks the model publisher pin and the agent validates the model
before first start. Preserve the exact bytes of the four files for
reproduction. Omit `--model-dir` for telemetry-only collection. The current
repository baseline failed the evaluation gate and cannot be shipped as an
approved model.

The distribution owner signs the exact `provenance.json` bytes with a
dedicated release signing certificate. For example, on the signing host
with OpenSSL and the release key available to the publisher:

```sh
openssl cms -sign -binary -md sha256 -nosmimecap \
  -in dist/provenance.json -signer release.crt -inkey release.key \
  -outform DER -out dist/provenance.p7s
openssl x509 -in release.crt -outform DER | sha256sum
```

Distribute the ZIP, provenance JSON and detached CMS signature together.
Publish the expected full commit and SHA-256 of the DER release certificate
through a trusted operator channel outside the download. Supply the installer
script from a trusted checkout at the reviewed commit. When rotating or
revoking a release signer, distribute the updated pin through that same
channel. The installer checks the pinned certificate and its current validity
period. The pin is the trust anchor for this CMS signature.

## Clean install

Obtain an unexpired one-use bootstrap JSON file from the deployment and its
trusted HTTPS enrollment origin. Create the file in an administrator-only
directory. The file ACL may grant access to SYSTEM, Administrators and the
installing administrator. Supply a CA PEM only when the controller requires
an explicit CA. Keep the input bootstrap file private and remove it once the
outcome is known. The installer provisions a private copy and the service
deletes that copy after enrollment.

```powershell
./packaging/windows/Install-DeviceAudit.ps1 `
    -PackageDir C:\Downloads\device-audit-release `
    -SignerSHA256 $releaseCertificatePin -SourceCommit $reviewedCommit `
    -EnrollmentOrigin 'https://enrollment.example.org' `
    -BootstrapFile C:\Private\bootstrap.json
```

For a model package, add `-ModelPublisherSHA256` with the independently
trusted SHA-256 of the exact publisher PEM. For mesh delivery, supply
`-MeshServerKey` (controller X25519 public key), `-DERPRegionFile` (approved
self-hosted region JSON) and `-ControllerAckKeyFile` (controller Ed25519
acknowledgement public key PEM) together. For assigned diagnostics add
`-DiagnosticControllerKeyFile`. With no mesh settings, the service retains
signed telemetry in its bounded local spool. Install success confirms a local
signed sample. Confirm controller receipt separately when enabling delivery.

The installer verifies the release signature, expected source and archive
digest before extracting or invoking package code. The service starts as
LocalService with a per-service SID and only `SeChangeNotifyPrivilege`.
The service can read the installed image and config and write its evidence
and identity state. It gets automatic startup and restart recovery after it
enrolls, queues its first signed endpoint sample and removes the provisioned
bootstrap. The signed release provenance is retained under
`%ProgramFiles%\DeviceAudit`. The package release signer, model publisher,
mesh identity, application signing and chain commitments have separate
trust roles.

## Failed or interrupted install

A first-start failure triggers rollback, including disabling and removing the
partial service and deleting the provisioned credential and the new local
state. The original private credential stays with the operator. Enrollment
may have finished on the controller before a later local failure. Check the
device admission and follow the controller's revocation or recovery procedure
before retrying with a new token.

If an interruption leaves a service or directories, clean install refuses
to reuse them. In an elevated shell, inspect the existing service and the
files under `%ProgramFiles%\DeviceAudit` and
`%ProgramData%\DeviceAudit\Endpoint`. For a failed attempt you own, disable
and remove its registration and purge its state with the trusted repository
copy of `tools/service/Uninstall-EndpointService.ps1 -PurgeState`. Remove the
remaining package files and empty parent directories before retrying. Remove
any private `DeviceAudit-install-*` staging directory identified by the
installer after an interrupted attempt.

For a successful installation, preserve or retire device state according to
the deployment's retention policy before purging it. Binary upgrades and
state-preserving reinstall need a separate path.

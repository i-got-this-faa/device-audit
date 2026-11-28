# PKG01 Windows package evidence

The [Windows package workflow](../../.github/workflows/windows-package.yml)
rebuilds the package twice from a single Git commit and compares the ZIP and
provenance bytes. It then signs the provenance with an ephemeral certificate
and moves the signed archive to a fresh `windows-2025` job. The smoke test
calls the normal installer entry point. It covers the wrong certificate,
wrong source commit, wrong model publisher, modified ZIP or provenance and an expired
bootstrap after service registration. Each rejected case requires the service
and the newly provisioned state to be absent. The success case requires a
configured bundled model, retained signed provenance, deleted provisioned
credential, and real Windows memory telemetry with an envelope that verifies
against the signing key admitted by the TLS enrollment fixture.

The packaging job uses an ephemeral model signer and a synthetic passing
evaluation. The enrollment fixture checks signing and mesh key possession.
The measurements come from the Windows collector. Production release ceremony
and certificate, physical Windows 11 fresh-machine install, real controller
admission and mesh delivery from the release installer, an approved
production model, and forced interruption of the installer remain separate
qualification work. The install touches no browser or chain behavior.

## Local checks

On Linux, `make check cross-build` passed with the pinned Python test
dependencies, including 104 Python tests. The Windows amd64 test binary
cross-compiled separately. `make browser-check` passed using the cached
Chromium from Playwright. PowerShell's parser accepted all three install and
uninstall scripts.

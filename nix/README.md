# Development dependency profiles

Enable Nix's `nix-command` and `flakes` experimental features. From the repository
root, run `nix develop` or `nix develop .#<profile>`.

- `default` combines Go, Python model/schema tests, project automation, Nix tools
  and PowerShell 7.6.7.
- `go` provides Go 1.27 and a C compiler for `go test -race`. Run `make build test lint cross-build`.
- `models` provides Python 3.12, jsonschema and RFC 3339 validation. Run `make model-check`.
- `automation` provides Node.js 24 for `node --test tools/project-sync.test.mjs`.
- `networking` provides the Go tools and, on Linux, strace and awk for the optional
  syscall proof. Run `make tailcat-lab-check tailcat-lab-proof`.
- `nix` provides nixfmt, statix and deadnix. Run `nix fmt`, `statix check` and `deadnix`.
- `powershell` provides PowerShell 7.6.7 for the portable probe regression suite:
  `nix develop .#powershell --command pwsh -NoLogo -NoProfile -File tools/probes/Test-WindowsProbe.ps1`.

Every shell includes Git, Make, curl and jq. The profiles in `profiles/` declare
package lists; `default.nix` composes them into shells. The default shell supports
`make contract-check check cross-build demo`; the Go-only shell omits the Python
dependencies needed by `make check`.

`flake.lock` pins Nixpkgs and therefore the compiler and Python package versions.
The Go profile selects the pinned Nixpkgs `go_1_27` package, satisfying the
`go.mod` minimum of 1.27.1. `GOTOOLCHAIN=local` prevents Go from silently downloading
another compiler; update the Nixpkgs lock when a module needs a newer toolchain.
The networking lab's Go modules remain pinned separately in its own module files.

Nix supplies the Python test libraries and their transitive dependencies without
a pip install. Their Nixpkgs versions can differ from the exact pip versions in
`models/test-requirements.txt` used by CI. To reproduce that pip environment,
follow the virtual-environment steps in the root README. No PyTorch, database
server, blockchain toolchain or frontend build runtime is added to these shells.

For direnv, install direnv and nix-direnv, hook direnv into your interactive shell,
and run `direnv allow` at the root. `.envrc` watches the profile files; nix-direnv
also watches `flake.nix` and `flake.lock`. `.direnv/` is ignored by Git.

The flake exposes shells for x86_64 and aarch64 Linux and Apple Silicon macOS.
The pinned Nixpkgs revision does not support Intel macOS. These are development
hosts, not additional qualified endpoint platforms. Native Windows
validation still uses `tools/check-windows.ps1` as documented in the root README.

After editing profiles, validate with:

```sh
nix fmt
nix flake check --all-systems
nix develop --command statix check
nix develop --command deadnix
nix develop --command make contract-check check cross-build demo
```

Update dependencies deliberately with `nix flake update nixpkgs`, then rerun the
checks and review the lock diff. When adding new Nix files, add them to Git before
using the Git-backed flake; Nix excludes untracked files from that source.

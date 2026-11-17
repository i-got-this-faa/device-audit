"""Classify changed paths for the scaffold and service-budget workflows.

Documentation paths are ignored before matching, so a markdown or image edit
inside a code tree does not schedule a job. Pushes to the default branch force
every Check scaffold job. A diff that cannot be resolved also forces the jobs
in the workflow being classified, which is safer than a false skip.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

CHECK_WORKFLOW = ".github/workflows/check.yml"
SERVICE_WORKFLOW = ".github/workflows/service-budget.yml"
FILTER_SCRIPT = "tools/ci/path_filters.py"
MAKEFILE = "Makefile"
GO_MODULE = ("go.mod", "go.sum")

# Packages `go test ./...` compiles from the root module, plus the non-Go
# files those tests and the model suite read. tailcat-lab is a separate module.
MODULE_GO = (
    "apps/controller/**",
    "apps/endpoint-agent/**",
    "apps/web-console/*.go",
    "apps/web-console/templates/**",
    "apps/web-console/static/**",
    "apps/web-console/fixtures/**",
    "contracts/**",
    "infra/**",
    "internal/**",
    "networking/mesh/**",
    "packages/**",
    "tools/fakes/**",
    "tools/probes/collectorbudget/**",
    "tools/probes/collectorservice/**",
    *GO_MODULE,
)
MODELS = ("models/**",)
SHARED_WITH_WINDOWS = (
    "tools/demo.py",
    "tools/contract_conformance.py",
    "models/test-requirements.txt",
)
WINDOWS_PROBES = (
    "tools/check-windows.ps1",
    "tools/probes/Test-WindowsProbe.ps1",
    "tools/probes/WindowsProbe.ps1",
    "tools/probes/Invoke-WindowsProbeWorker.ps1",
    "tools/probes/Export-WindowsProbeEvidence.ps1",
)

# browser-check compiles internal/controller/auth (including the Postgres store
# tests and the embedded web-console package) and then runs the Node suite.
CONSOLE_BROWSER = (
    "apps/web-console/**",
    "infra/database/**",
    "internal/controller/auth/**",
    "packages/contracts/*.go",
    MAKEFILE,
    *GO_MODULE,
    CHECK_WORKFLOW,
    FILTER_SCRIPT,
)
# check-windows.ps1 reimplements vet, race, fmt, model tests, fakes, demo and
# cross-builds. It does not invoke make or the replay smoke script.
WINDOWS_CHECK = (
    *MODULE_GO,
    *MODELS,
    *SHARED_WITH_WINDOWS,
    *WINDOWS_PROBES,
    CHECK_WORKFLOW,
    FILTER_SCRIPT,
)
PROJECT_AUTOMATION = (
    "tools/project-sync.mjs",
    "tools/project-sync.test.mjs",
    CHECK_WORKFLOW,
    FILTER_SCRIPT,
)
CHECK = (
    *MODULE_GO,
    *MODELS,
    *SHARED_WITH_WINDOWS,
    "tools/replay_smoke.py",
    MAKEFILE,
    CHECK_WORKFLOW,
    FILTER_SCRIPT,
)
TAILCAT_LAB = (
    "networking/tailcat-lab/**",
    MAKEFILE,
    CHECK_WORKFLOW,
    FILTER_SCRIPT,
)
# database-check tests these packages. Endpoint and controller tests read two
# contract fixture files; other contract fixtures are not inputs.
DATABASE = (
    "apps/controller/**",
    "apps/endpoint-agent/**",
    "apps/web-console/*.go",
    "apps/web-console/templates/**",
    "apps/web-console/static/**",
    "apps/web-console/fixtures/**",
    "infra/database/**",
    "internal/controller/**",
    "networking/mesh/**",
    "packages/contracts/*.go",
    "packages/contracts/fixtures/envelopes/**",
    "packages/contracts/fixtures/telemetry/**",
    MAKEFILE,
    *GO_MODULE,
    CHECK_WORKFLOW,
    FILTER_SCRIPT,
)
DATASET_REPRODUCTION = (
    "models/src/device_audit_models/partitions.py",
    "models/src/device_audit_models/__init__.py",
    "models/datasets/backblaze-2013/**",
    CHECK_WORKFLOW,
    FILTER_SCRIPT,
)
# Invoke-ServiceTokenBudget builds both probe binaries and runs the sensor
# scripts they launch. It does not call make. Root go.mod selects the toolchain.
SERVICE_TOKEN_BUDGET = (
    "tools/probes/service-budget.trigger",
    "tools/probes/Invoke-ServiceTokenBudget.ps1",
    "tools/probes/Measure-WindowsSensors.ps1",
    "tools/probes/WindowsProbe.ps1",
    "tools/probes/Invoke-WindowsProbeWorker.ps1",
    "tools/probes/collectorservice/**",
    "tools/probes/collectorbudget/**",
    "packages/telemetry/**",
    "packages/contracts/*.go",
    *GO_MODULE,
    SERVICE_WORKFLOW,
    FILTER_SCRIPT,
)

WORKFLOWS = {
    "check": {
        "console_browser": CONSOLE_BROWSER,
        "windows_check": WINDOWS_CHECK,
        "project_automation": PROJECT_AUTOMATION,
        "check": CHECK,
        "tailcat_lab": TAILCAT_LAB,
        "database": DATABASE,
        "dataset_reproduction": DATASET_REPRODUCTION,
    },
    "service-budget": {
        "service_token_budget": SERVICE_TOKEN_BUDGET,
    },
}

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp"}
ZERO = "0" * 40


def is_documentation(path: str) -> bool:
    """True for docs, markdown, readme, license text and images."""
    normalized = path.strip().strip("/")
    if normalized == "docs" or normalized.startswith("docs/"):
        return True
    name = normalized.rsplit("/", 1)[-1]
    if name.lower().endswith(".md"):
        return True
    upper = name.upper()
    if upper == "README" or upper.startswith("README."):
        return True
    if upper.startswith(("LICENSE", "COPYING", "UNLICENSE")) or upper.endswith("LICENSE"):
        return True
    suffix = Path(name).suffix.lower()
    return suffix in IMAGE_EXTENSIONS


def matches(path: str, pattern: str) -> bool:
    """Match path against a glob where * stays inside one segment and ** crosses."""
    return _match(_segments(path), _segments(pattern))


def classify(paths: list[str], workflow: str, *, force: bool = False) -> dict[str, bool]:
    jobs = WORKFLOWS[workflow]
    if force:
        return {name: True for name in jobs}
    selected = {name: False for name in jobs}
    for path in paths:
        if is_documentation(path):
            continue
        for name, patterns in jobs.items():
            if selected[name]:
                continue
            if any(matches(path, pattern) for pattern in patterns):
                selected[name] = True
    return selected


def decide(
    repo: Path,
    *,
    workflow: str,
    event_name: str,
    ref: str,
    sha: str,
    before: str,
    base_sha: str,
    head_sha: str,
    default_branch: str,
) -> tuple[bool, list[str]]:
    """Return (force, paths). force schedules every job of this workflow."""
    if workflow not in WORKFLOWS:
        raise ValueError(f"unknown workflow {workflow}")
    if event_name == "workflow_dispatch":
        return True, []
    default_ref = f"refs/heads/{default_branch}"
    if workflow == "check" and event_name == "push" and ref == default_ref:
        return True, []
    if event_name == "pull_request":
        if not base_sha or not head_sha:
            return True, []
        if not _ensure_commit(repo, base_sha) or not _ensure_commit(repo, head_sha):
            return True, []
        return False, _diff(repo, f"{base_sha}...{head_sha}")
    if event_name == "push":
        if not before or before == ZERO:
            base = _branch_tip(repo, default_branch)
            if base and sha and _have(repo, sha):
                return False, _diff(repo, f"{base}...{sha}")
            return True, []
        if not _ensure_commit(repo, before) or not sha or not _ensure_commit(repo, sha):
            return True, []
        return False, _diff(repo, f"{before}..{sha}")
    return True, []


def main() -> int:
    repo = Path.cwd()
    workflow = os.environ.get("CI_WORKFLOW", "check")
    test = Path(__file__).with_name("path_filters_test.py")
    completed = subprocess.run([sys.executable, str(test)], cwd=repo)
    if completed.returncode != 0:
        return completed.returncode
    force, paths = decide(
        repo,
        workflow=workflow,
        event_name=os.environ.get("CI_EVENT_NAME", ""),
        ref=os.environ.get("CI_REF", ""),
        sha=os.environ.get("CI_SHA", ""),
        before=os.environ.get("CI_BEFORE", ""),
        base_sha=os.environ.get("CI_BASE_SHA", ""),
        head_sha=os.environ.get("CI_HEAD_SHA", ""),
        default_branch=os.environ.get("CI_DEFAULT_BRANCH", "main"),
    )
    flags = classify(paths, workflow, force=force)
    selected = [name for name, enabled in flags.items() if enabled]
    print(f"event={os.environ.get('CI_EVENT_NAME', '')} force={force} files={len(paths)}")
    print("selected: " + (", ".join(selected) if selected else "(none)"))
    payload = "".join(f"{name}={'true' if enabled else 'false'}\n" for name, enabled in flags.items())
    sys.stdout.write(payload)
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(payload)
    return 0


def _segments(value: str) -> list[str]:
    return [segment for segment in value.strip().strip("/").split("/") if segment]


def _match(path: list[str], pattern: list[str]) -> bool:
    if not pattern:
        return not path
    if pattern[0] == "**":
        if len(pattern) == 1:
            return True
        return any(_match(path[index:], pattern[1:]) for index in range(len(path) + 1))
    if not path:
        return False
    if _segment_match(path[0], pattern[0]):
        return _match(path[1:], pattern[1:])
    return False


def _segment_match(segment: str, pattern: str) -> bool:
    if pattern == "*":
        return True
    if "*" not in pattern and "?" not in pattern:
        return segment == pattern
    # fnmatch's * crosses nothing here because the segment contains no slash.
    from fnmatch import fnmatchcase

    return fnmatchcase(segment, pattern)


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _have(repo: Path, sha: str) -> bool:
    return _git(repo, "cat-file", "-e", f"{sha}^{{commit}}", check=False).returncode == 0


def _ensure_commit(repo: Path, sha: str) -> bool:
    if _have(repo, sha):
        return True
    fetched = _git(repo, "fetch", "--no-tags", "origin", sha, check=False)
    return fetched.returncode == 0 and _have(repo, sha)


def _branch_tip(repo: Path, name: str) -> str | None:
    for candidate in (f"origin/{name}", name):
        if _git(repo, "rev-parse", "--verify", "--quiet", candidate, check=False).returncode == 0:
            return candidate
    return None


def _diff(repo: Path, spec: str) -> list[str]:
    completed = _git(repo, "diff", "-z", "--name-status", spec)
    return _paths_from_name_status(completed.stdout)


def _paths_from_name_status(blob: bytes) -> list[str]:
    parts = blob.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    paths: list[str] = []
    index = 0
    while index < len(parts):
        status = parts[index].decode()
        index += 1
        if status.startswith(("R", "C")):
            old = parts[index].decode()
            new = parts[index + 1].decode()
            index += 2
            paths.extend((old, new))
            continue
        paths.append(parts[index].decode())
        index += 1
    return paths


if __name__ == "__main__":
    sys.exit(main())

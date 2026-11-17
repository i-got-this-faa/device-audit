"""Lock the job-to-path map and the diff used to feed it."""

import subprocess
import tempfile
import unittest
from pathlib import Path

GIT_QUIET = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}

import path_filters as filters


class ClassifyTests(unittest.TestCase):
    def selected(self, workflow, *paths, force=False):
        flags = filters.classify(list(paths), workflow, force=force)
        return {name for name, enabled in flags.items() if enabled}

    def test_documentation_schedules_nothing(self):
        paths = [
            "docs/requirements.md",
            "README.md",
            "README",
            "LICENSE",
            "LICENSE.txt",
            "networking/tailcat-lab/README.md",
            "networking/tailcat-lab/TAILCAT-LICENSE",
            "networking/tailcat-lab/evidence/2026-10-16.md",
            "docs/validation/screen.png",
            "apps/web-console/static/mark.svg",
            "AGENTS.md",
        ]
        self.assertEqual(self.selected("check", *paths), set())
        self.assertEqual(self.selected("service-budget", *paths), set())

    def test_code_beside_docs_still_matches(self):
        self.assertEqual(
            self.selected("check", "docs/requirements.md", "networking/tailcat-lab/direct_test.go"),
            {"tailcat_lab"},
        )

    def test_browser_assets_do_not_run_windows_or_database(self):
        self.assertEqual(
            self.selected("check", "apps/web-console/tests/browser.mjs", "apps/web-console/package-lock.json"),
            {"console_browser"},
        )

    def test_embedded_console_runs_go_jobs_and_browser(self):
        self.assertEqual(
            self.selected("check", "apps/web-console/static/console.js"),
            {"console_browser", "windows_check", "check", "database"},
        )

    def test_tailcat_go_is_only_the_lab_job(self):
        self.assertEqual(
            self.selected("check", "networking/tailcat-lab/direct_test.go"),
            {"tailcat_lab"},
        )

    def test_makefile_runs_make_targets_only(self):
        self.assertEqual(
            self.selected("check", "Makefile"),
            {"console_browser", "check", "tailcat_lab", "database"},
        )
        self.assertEqual(self.selected("service-budget", "Makefile"), set())

    def test_root_module_files_skip_the_independent_lab(self):
        selected = self.selected("check", "go.mod")
        self.assertIn("windows_check", selected)
        self.assertIn("check", selected)
        self.assertIn("database", selected)
        self.assertIn("console_browser", selected)
        self.assertNotIn("tailcat_lab", selected)
        self.assertNotIn("dataset_reproduction", selected)
        self.assertNotIn("project_automation", selected)
        self.assertEqual(self.selected("service-budget", "go.sum"), {"service_token_budget"})

    def test_check_workflow_runs_its_jobs_and_not_the_service_budget(self):
        self.assertEqual(
            self.selected("check", ".github/workflows/check.yml"),
            set(filters.WORKFLOWS["check"]),
        )
        self.assertEqual(self.selected("service-budget", ".github/workflows/check.yml"), set())

    def test_service_workflow_is_the_service_job(self):
        self.assertEqual(
            self.selected("service-budget", ".github/workflows/service-budget.yml"),
            {"service_token_budget"},
        )
        self.assertEqual(self.selected("check", ".github/workflows/service-budget.yml"), set())

    def test_partitions_skip_postgres(self):
        self.assertEqual(
            self.selected("check", "models/src/device_audit_models/partitions.py"),
            {"windows_check", "check", "dataset_reproduction"},
        )

    def test_other_model_code_skips_the_archive_job(self):
        self.assertEqual(
            self.selected("check", "models/src/device_audit_models/federated.py"),
            {"windows_check", "check"},
        )

    def test_auth_compiles_into_browser_database_and_module_tests(self):
        self.assertEqual(
            self.selected("check", "internal/controller/auth/console_test.go"),
            {"console_browser", "windows_check", "check", "database"},
        )

    def test_controller_change_skips_browser_and_tailcat(self):
        self.assertEqual(
            self.selected("check", "internal/controller/http.go"),
            {"windows_check", "check", "database"},
        )

    def test_replay_smoke_is_only_the_ubuntu_check(self):
        self.assertEqual(self.selected("check", "tools/replay_smoke.py"), {"check"})

    def test_project_sync_is_only_its_node_job(self):
        self.assertEqual(
            self.selected("check", "tools/project-sync.mjs"),
            {"project_automation"},
        )

    def test_windows_probe_split_from_the_service_measurement(self):
        self.assertEqual(
            self.selected("check", "tools/probes/Test-WindowsProbe.ps1"),
            {"windows_check"},
        )
        self.assertEqual(
            self.selected("service-budget", "tools/probes/Measure-WindowsSensors.ps1"),
            {"service_token_budget"},
        )
        self.assertEqual(self.selected("check", "tools/probes/Measure-WindowsSensors.ps1"), set())
        self.assertEqual(
            self.selected("check", "tools/probes/WindowsProbe.ps1"),
            {"windows_check"},
        )
        self.assertEqual(
            self.selected("service-budget", "tools/probes/WindowsProbe.ps1"),
            {"service_token_budget"},
        )

    def test_contract_library_reaches_importers_and_fixtures_do_not(self):
        self.assertIn("console_browser", self.selected("check", "packages/contracts/envelopes_v1.go"))
        self.assertEqual(
            self.selected("service-budget", "packages/contracts/envelopes_v1.go"),
            {"service_token_budget"},
        )
        self.assertEqual(
            self.selected("check", "packages/contracts/fixtures/audit/v1-vectors.json"),
            {"windows_check", "check"},
        )
        self.assertEqual(
            self.selected("check", "packages/contracts/fixtures/envelopes/v1-vectors.json"),
            {"windows_check", "check", "database"},
        )

    def test_filter_script_reruns_every_gated_job(self):
        self.assertEqual(self.selected("check", "tools/ci/path_filters.py"), set(filters.WORKFLOWS["check"]))
        self.assertEqual(
            self.selected("service-budget", "tools/ci/path_filters.py"),
            {"service_token_budget"},
        )

    def test_unrelated_files_schedule_nothing(self):
        self.assertEqual(self.selected("check", "flake.nix", "flake.lock", "nix/README.md"), set())

    def test_force_enables_every_job_in_the_workflow(self):
        self.assertEqual(self.selected("check", "docs/requirements.md", force=True), set(filters.WORKFLOWS["check"]))


class DiffTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        subprocess.check_call(["git", "init", "-b", "main", self.repo], **GIT_QUIET)
        subprocess.check_call(["git", "-C", self.repo, "config", "user.email", "test@example.com"])
        subprocess.check_call(["git", "-C", self.repo, "config", "user.name", "Test"])

    def tearDown(self):
        self.tmp.cleanup()

    def commit(self, rel, content="x"):
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        subprocess.check_call(["git", "-C", self.repo, "add", rel], **GIT_QUIET)
        subprocess.check_call(["git", "-C", self.repo, "commit", "-m", rel], **GIT_QUIET)
        return subprocess.check_output(["git", "-C", self.repo, "rev-parse", "HEAD"], text=True).strip()

    def test_pull_request_uses_the_merge_base(self):
        base = self.commit("apps/controller/main.go")
        subprocess.check_call(["git", "-C", self.repo, "switch", "-c", "feature"], **GIT_QUIET)
        head = self.commit("docs/only.md")
        subprocess.check_call(["git", "-C", self.repo, "switch", "main"], **GIT_QUIET)
        main_tip = self.commit("internal/controller/http.go")
        force, paths = filters.decide(
            self.repo,
            workflow="check",
            event_name="pull_request",
            ref="refs/pull/1/merge",
            sha=main_tip,
            before="",
            base_sha=main_tip,
            head_sha=head,
            default_branch="main",
        )
        self.assertFalse(force)
        self.assertEqual(paths, ["docs/only.md"])
        self.assertNotEqual(base, head)

    def test_push_range_is_only_the_new_commit(self):
        before = self.commit("apps/controller/main.go")
        sha = self.commit("README.md")
        force, paths = filters.decide(
            self.repo,
            workflow="check",
            event_name="push",
            ref="refs/heads/feature",
            sha=sha,
            before=before,
            base_sha="",
            head_sha="",
            default_branch="main",
        )
        self.assertFalse(force)
        self.assertEqual(paths, ["README.md"])

    def test_main_push_forces_the_scaffold_only(self):
        before = self.commit("apps/controller/main.go")
        sha = self.commit("docs/requirements.md")
        force, paths = filters.decide(
            self.repo,
            workflow="check",
            event_name="push",
            ref="refs/heads/main",
            sha=sha,
            before=before,
            base_sha="",
            head_sha="",
            default_branch="main",
        )
        self.assertTrue(force)
        self.assertEqual(paths, [])
        service_force, service_paths = filters.decide(
            self.repo,
            workflow="service-budget",
            event_name="push",
            ref="refs/heads/main",
            sha=sha,
            before=before,
            base_sha="",
            head_sha="",
            default_branch="main",
        )
        self.assertFalse(service_force)
        self.assertEqual(service_paths, ["docs/requirements.md"])

    def test_new_branch_compares_with_the_default_branch(self):
        self.commit("apps/controller/main.go")
        subprocess.check_call(["git", "-C", self.repo, "switch", "-c", "feature"], **GIT_QUIET)
        sha = self.commit("tools/project-sync.mjs")
        force, paths = filters.decide(
            self.repo,
            workflow="check",
            event_name="push",
            ref="refs/heads/feature",
            sha=sha,
            before="0" * 40,
            base_sha="",
            head_sha="",
            default_branch="main",
        )
        self.assertFalse(force)
        self.assertEqual(paths, ["tools/project-sync.mjs"])

    def test_rename_reports_both_paths(self):
        self.commit("tools/replay_smoke.py", "print('ok')\n")
        subprocess.check_call(["git", "-C", self.repo, "mv", "tools/replay_smoke.py", "tools/replay_smoke_renamed.py"], **GIT_QUIET)
        subprocess.check_call(["git", "-C", self.repo, "commit", "-m", "rename"], **GIT_QUIET)
        blob = subprocess.check_output(["git", "-C", self.repo, "diff", "-z", "--name-status", "HEAD~1", "HEAD"])
        self.assertEqual(
            filters._paths_from_name_status(blob),
            ["tools/replay_smoke.py", "tools/replay_smoke_renamed.py"],
        )

    def test_dispatch_forces_the_workflow(self):
        force, paths = filters.decide(
            self.repo,
            workflow="service-budget",
            event_name="workflow_dispatch",
            ref="refs/heads/main",
            sha="",
            before="",
            base_sha="",
            head_sha="",
            default_branch="main",
        )
        self.assertTrue(force)
        self.assertEqual(paths, [])


if __name__ == "__main__":
    unittest.main()

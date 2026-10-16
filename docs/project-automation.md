# Automatic roadmap tracking

[Project 7](https://github.com/orgs/i-got-this-faa/projects/7) uses issue cards as
the source of work, native parent/blocker relationships for structure, and linked
PRs as implementation evidence. Its views are filters over those same cards;
moving Status changes every applicable view, including **Ready to pick**.

## Lifecycle

The `Reconcile project 7` workflow runs after issue/PR changes and every 15 minutes
at minutes 7, 22, 37 and 52. GitHub can delay scheduled runs; this is eventual
reconciliation, not a real-time guarantee. It also supports a manual dry run.

| Evidence | Result |
| --- | --- |
| Issue is closed | Done |
| `automation:hold` label | Blocked, until the hold is removed |
| Open, non-draft PR with a closing issue link | In review |
| Current Blocked card still has unfinished prerequisites | Remains Blocked |
| Open partial/reference PR, or a draft closing PR | In progress |
| `automation:started` label, or a manually started In progress card | In progress |
| Idle task with unfinished prerequisites | Blocked |
| Triaged task whose prerequisites completed | Ready |
| New task without a Dependencies section | Backlog for triage |

An empty `## Dependencies` section or `- None` declares that a task has been
triaged. An issue closed as **not planned** does not satisfy a prerequisite:
remove or replace that dependency intentionally. Active/review work may still
have the native blocked icon; the automation never presents it as Ready.

Containers roll up child activity to In progress, and all-finished children to
In review. An owner must still verify and close the parent. The reconciler does
not close issues or merge PRs. Archived cards stay archived. Unrelated custom
fields, estimates, sizes, requirement mappings and manual relationship additions
are preserved.

For a hold that must survive dependency completion, add `automation:hold`.
To start work without a draft PR, drag its card to In progress or add
`automation:started`. Remove the started label and move the card back to Backlog
when abandoning that start. Closed issues always resolve to Done.

## Link a PR once

Use **`Closes #123`** only when merging the PR completes the entire issue. Use
**`Refs #123`** for partial work. Existing manually selected Development links
also count as closing links. GitHub performs the issue closure itself; the
workflow never infers completion from a merge alone.

The reconciler reads local `Refs`, `References`, `Relates to`, `Closes`, `Fixes`
and `Resolves` references, including explicit local GitHub issue URLs. Code
examples, quoted text, comments and references to other repositories are ignored.
An unreferenced `issue/123-description` branch gets a non-closing `Refs #123`
only when that issue exists. Otherwise the run summary identifies the PR for
triage rather than guessing an issue or completion claim.

PRs inherit the referenced issues' `area:`, `kind:`, `lane:`, `priority:` and
`weeks:` labels. Multi-issue PRs receive their union; unrelated labels are
preserved. Issue labels maintain project Kind, Lane, Area, Priority and Week.
Referenced PRs are also added to Project 7. Their Status is In review for an
open non-draft, In progress for a draft, Done for a merge, and Backlog for a
closed, unmerged PR. This tracks the PR's review lifecycle separately from its
issue's completion. Archived PR cards stay archived. PR taxonomy fields use the
same labels; multiple values for a single-select field are reported for manual
selection rather than arbitrarily choosing one.

An unassigned PR inherits the union of its referenced issues' owners (up to
GitHub's ten-assignee limit). A PR without a milestone inherits it only when
every referenced issue has the same milestone. Existing PR assignments and
milestones are preserved, including edits made between preview and apply.
Missing or conflicting source metadata remains a manual triage decision.
Native assignees, milestones and labels then appear in Projects automatically.
An issue's `## Dependencies` list and `Parent: #N` declaration add missing native
links. Conflicting parents, cycles, missing targets/options and truncated API
connections stop the run before writes. Removing a declaration does not delete
a manually maintained relationship.

## One-time activation

The built-in close-to-Done, merge-to-Done and link-to-In-review rules work without
this workflow. **Dependency-based Ready movement needs the credential below.**
The normal repository `GITHUB_TOKEN` does not authorize organization Projects.
The workflow is inactive until explicitly enabled; it does not copy a developer's
CLI login or extract browser credentials.

1. Have an organization owner register a private GitHub App owned by
   `i-got-this-faa`. Disable webhooks and user authorization: Actions supplies
   the triggers, and the App acts as its own bot. Grant only:

   - Organization **Projects: read and write** (repository Projects is a
     different permission and is insufficient).
   - Repository **Issues: read and write** and **Pull requests: read and write**.
   - Repository **Metadata: read-only**, which GitHub adds automatically.

   Install it on **only `device-audit`**. Organization Projects permission is
   organization-wide; the reconciler itself is fixed to Project 7. The App
   does not need Contents write, Actions, Administration, Workflows, Secrets,
   Members, or personal-account permissions.
2. Store the App's client ID in the repository Actions variable
   `PROJECT_AUTOMATION_APP_CLIENT_ID`. Generate an App private key and store it
   directly in the Actions secret `PROJECT_AUTOMATION_APP_PRIVATE_KEY`. Do not
   paste the key into an issue, PR, chat, or tracked file. The pinned official
   `actions/create-github-app-token` action mints a fresh installation token
   for each run, restricted to `device-audit` and the three write permissions
   above; its post step revokes that token when the job finishes. No personal
   CLI credential is copied into Actions.

   The existing PAT option remains available for installations that already
   use `PROJECT_AUTOMATION_TOKEN`: a classic PAT needs `repo` and `project`
   scopes, an expiry, and organization/SSO approval where required. App
   authentication takes precedence. A partially configured App fails before
   reconciliation instead of silently falling back to the PAT. Never store a
   temporary installation token in this PAT secret as a permanent credential.
3. Create the control labels once, if absent:

   ```sh
   gh label create automation:hold --repo i-got-this-faa/device-audit --color B60205 --description "Manual blocker; automation must keep this work Blocked"
   gh label create automation:started --repo i-got-this-faa/device-audit --color 1D76DB --description "Work started before an implementation PR exists"
   ```

4. Run **Reconcile project 7** manually with `apply: false`. Inspect its summary
   and `project-7-plan` artifact. This previews all changes and checks access to
   the actual project, fields, options, iterations and every page of cards.
5. Run it with `apply: true`. It reads back GitHub after applying and succeeds
   only when a second plan contains zero remaining writes.
6. Set repository Actions variable `PROJECT_AUTOMATION_ENABLED` to `true` to
   enable continuous event/scheduled reconciliation. Set it to `false` to stop
   the custom reconciler while retaining the built-in rules.

Changes to dependencies made directly in the relationship UI, and manual board
drags, are caught by the scheduled pass. Issue closure/reopening runs immediately
through the issue event. Runs serialize through one concurrency group, and a
converged run makes no writes. A PAT's label events may enqueue another pass;
the next pass is a no-op. A failed/expired credential makes the run fail visibly.

`pull_request_target` executes only trusted **default-branch** code with a pinned
checkout and Node setup. It never checks out a PR head, installs PR dependencies,
or interpolates PR text into a shell. The credential is used only by `gh api`.
An App installation token is created per run and revoked at job completion.
Rotate the App private key when required by the organization's credential policy:
add the replacement Actions secret before revoking the old App key. If using
the optional PAT, rotate it before its expiry. Expired or revoked credentials
fail visibly; disabling `PROJECT_AUTOMATION_ENABLED` pauses reconciliation.

## Verification

```sh
node --test tools/project-sync.test.mjs
node tools/project-sync.mjs --repository-only --output repository-plan.json
node tools/project-sync.mjs --output project-plan.json
node tools/project-sync.mjs --apply --output applied-plan.json
```

The first preview only reads repository metadata: it cannot validate project
field IDs or preserve current project-only status choices. Full previews require
Projects access. The tests exercise lifecycle transitions, holds, partial PRs,
reopening, metadata reconciliation, pagination, invalid relationships, safe
reference parsing and no-op convergence. They do not substitute for the first
live project preview/apply/read-back; record that run URL before claiming full
automation is active.

GitHub references:

- [Built-in workflows](https://docs.github.com/en/issues/planning-and-tracking-with-projects/automating-your-project/using-the-built-in-automations)
- [Projects API and authentication](https://docs.github.com/en/issues/planning-and-tracking-with-projects/automating-your-project/using-the-api-to-manage-projects)
- [Automating Projects with Actions](https://docs.github.com/en/issues/planning-and-tracking-with-projects/automating-your-project/automating-projects-using-actions)
- [Native issue dependencies](https://docs.github.com/en/issues/tracking-your-work-with-issues/using-issues/creating-issue-dependencies)

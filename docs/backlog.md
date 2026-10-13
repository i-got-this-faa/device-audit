# Focused implementation backlog

Items are unscheduled until the PDF and delivery constraints are verified.

1. **Source verification:** obtain the PDF, hash it, map exact requirements,
   settle patent-specific scope and acceptance criteria.
2. **Network spike:** implement the Tailcat adapter and self-hosted DERP using
   a tested pinned revision; verify key persistence, admission, identity binding,
   revocation, reconnect, direct LAN/WAN and UDP-blocked relay operation.
3. **Identity + persistence:** authenticated enrollment, per-device signatures,
   sequence/replay handling, PostgreSQL migrations, bounded offline spool.
4. **Real Windows telemetry:** implement read-only sensor/log collectors,
   explicit missing sensors, preprocessing, sampling and resource budgets.
5. **Bespoke model baseline:** select datasets/labels/features/horizon, train
   and evaluate, version artifacts, measure endpoint inference cost.
6. **Autonomous local diagnostics:** health-specific scheduled/event-triggered
   workflows, typed probe catalog, evidence references and retry/deadline limits.
7. **Federated training:** two-device local training, authenticated compatible
   updates, scheduled rounds, aggregation, poisoning/privacy analysis and gated
   promotion against held-out evaluation.
8. **Audit + lifecycle:** report generation and evidence-backed repair/upgrade/
   replacement decisions; sustainability/longevity methodology and uncertainty.
9. **Smart contracts:** choose chain/permissions, define canonical commitments,
   implement and test authorization/replay/finality, connect the Anchorer.
10. **Dashboard + full demonstration:** choose UI framework, health/fleet views,
    audit evidence/receipts, model-round views, asset integration where required,
    and a traceable end-to-end demonstration of verified patent requirements.

This backlog replaces Shepherd's configuration manager delivery plan for this
repository. It does not migrate or close any Shepherd issue or project item.

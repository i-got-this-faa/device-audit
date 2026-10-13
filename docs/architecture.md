# Architecture boundaries

The endpoint is a lightweight Go service with read-only platform collectors,
preprocessing, a future custom inference worker, and a local training worker.
Cheap sampling is independent of inference/training cadence. Raw log text is
data, never authority to run commands. Remote work uses typed diagnostic jobs.

The Go controller owns device enrollment, ingestion, health state, diagnostic
assignment, federated rounds, model promotion, audit reports and asset metadata.
Separate interfaces keep model inference, lifecycle decisions, and blockchain
receipts from becoming one untestable agent loop.

The wire contracts reserve telemetry, model update metadata, model-versioned
predictions, expiring diagnostic tasks, and audit/sustainability results. Only
telemetry ingestion and latest-sample retrieval have HTTP routes in this
scaffold. Future endpoints must authenticate the transport peer, bind it to the
device identity, validate signatures/sequence counters, and reject replay.

Steady-state endpoint/controller traffic uses Shepherd's Tailcat/WireGuard
design with direct UDP connectivity and self-hosted DERP fallback. Enrollment
and administrator access require explicit HTTPS bootstrap/public surfaces.
The demo's loopback HTTP path is separate from production mesh transport.

Python contains framework-independent prediction/training interfaces and one
weighted model-vector averaging primitive. It contains no learned model,
failure predictor, dataset, coordinator, privacy guarantee or model promotion.
Before choosing PyTorch, validate a local training/inference runtime on the
target machines, define labels and temporal validation, and measure overhead.

Lifecycle analysis combines device evidence, validated predictions, hardware
age, repair/upgrade/replacement cost, and documented sustainability factors.
Missing inputs produce insufficient evidence or nullable outputs, not invented
carbon or lifetime numbers. No autonomous remediation executor is included.

Off-chain evidence storage and signatures supply the material for an audit
commitment. A future contract adapter anchors opaque IDs and commitments and
returns finality-aware receipts. The chain cannot prove the underlying host is
honest. Tenant access rules, identity rotation, replay handling and evidence
retention remain necessary alongside any smart contract.

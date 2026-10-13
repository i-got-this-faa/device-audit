# Provisional patent implementation map

Source priority: original patent PDF → explicit current user instructions →
latest explicit handoff decisions → earlier discussion and Shepherd documents.
The PDF is missing from this environment. The supplied transcript and
Shepherd's patent map are secondary interpretations, not verified claim text.
No claim number, document date, or legal coverage is asserted here.

| Capability described in secondary sources | Owner | Scaffold status | Acceptance evidence to build |
| --- | --- | --- | --- |
| Acquire device CPU/GPU, memory, disk, network, battery, temperature and error information | endpoint + telemetry | CPU/memory fixtures only; other nullable fields defined | Real Windows sensor/log evidence, sensor availability and sampling overhead |
| Preprocess and analyze device faults/anomalies | health + models | inference interface | Versioned features, validation data, measured false positives |
| Predict failures and assign health | health + controller | prediction type; unknown health in demo | Trained bespoke model, defined prediction horizon, held-out results |
| Assign local agents based on health | controller + workflows | diagnostic task/runner interfaces | Health-triggered bounded, authenticated read-only job |
| Train locally and aggregate model updates | models + federated | training interface and vector weighted-average primitive | At least two endpoints train locally; version-compatible updates aggregate and improve evaluated model |
| Run autonomous diagnostic workflows | workflows + endpoint | interface | Scheduled/event-triggered diagnostics with evidence and budget limits |
| Recommend repair, upgrade or replacement | lifecycle + audit | report/recommendation types | Recommendations grounded in telemetry, prediction and cost inputs |
| Estimate sustainability and longevity | lifecycle | nullable methodology-tagged outputs | Documented assumptions, units, uncertainty and measured inputs |
| Fleet/component trend analysis and asset integration | controller + integrations (future) | backlog only | Cross-device aggregation and an asset adapter where PDF requires them |

Custom prediction models and smart-contract audit verification are explicit
handoff decisions. Whether smart contracts, independent network observation,
or a particular security mechanism are required by the original patent remains
unverified. Integrity verification must not be described as endpoint truth
verification. The system reads machine evidence; a general web-browsing agent
and an LLM on every device are not prerequisites.

## PDF verification gate

1. Obtain the original `patent.pdf` and record its SHA-256 digest.
2. Extract all claims, referenced embodiments, diagrams and metric definitions.
3. Replace this provisional map with exact page/paragraph/claim references.
4. Reconcile differences with the transcript and explicitly record scope changes.

Keep source document dates unresolved: Shepherd's map and the transcript give
different dates. The PDF must settle this, not a guess from chat history.

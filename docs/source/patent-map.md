# Supplied PDF provenance, references and scope reconciliation

## Source and verification

The source is `/home/radhey/Downloads/patent.pdf`. The supplied PDF has 31 pages and is 595,967 bytes. Its SHA-256 digest is `f06a9046a10b76495176303c228cdcfe8a0bbe560efe564782055908f8a0a771`.

A second read on 14 October 2026 reproduced the same digest, byte count, and page inventory. The printed page numbers run from 1 through 31 and match the corresponding PDF page numbers.

On 15 October 2026 the user supplied the Windows copy at
`C:/Users/radhe/Downloads/patent.pdf`. A fresh SHA-256 read reproduced the same
digest and 595,967-byte size. `pypdf` extracted all 31 pages; rendered pages
26-29 were checked against the ten printed claims, and rendered pages 30-31
were inspected for the available figures. The Linux path above records the
earlier source location. Neither copy is committed to this repository.

Recheck the file with:

```sh
sha256sum /home/radhey/Downloads/patent.pdf
pdfinfo /home/radhey/Downloads/patent.pdf | grep -E '^(Pages|File size):'
pdftotext -layout /home/radhey/Downloads/patent.pdf -
pdftotext -bbox-layout /home/radhey/Downloads/patent.pdf -
```

The text extraction exposes paragraph and claim labels page by page. The bounding-box extraction includes printed footer labels. Render the two drawing pages to inspect the figures:

```sh
pdftoppm -f 30 -l 31 -png /home/radhey/Downloads/patent.pdf /tmp/patent-page
```

## Page inventory

The first number in each page reference is the PDF page. The second is the printed page. They match on all 31 pages. Paragraph labels below are transcribed as printed. A continuation entry identifies a paragraph that crosses a page break. The source prints paragraph labels [00100]–[00110] with five digits; these labels are retained verbatim.

| PDF page / printed page | Contents |
| --- | --- |
| 1 / 1 | Form 2 title, applicant details, and preamble to the description. |
| 2 / 2 | Paragraphs [0001]–[0006]. |
| 3 / 3 | Paragraphs [0007]–[0016]. |
| 4 / 4 | Paragraphs [0017]–[0026]. |
| 5 / 5 | Paragraphs [0027]–[0028] begin. |
| 6 / 6 | Paragraph [0028] continues; paragraphs [0029]–[0034] begin. Paragraph [0034] continues on page 7. |
| 7 / 7 | Paragraph [0034] continues; paragraphs [0035]–[0040]. |
| 8 / 8 | Paragraphs [0041]–[0043] begin. Paragraph [0043] continues on page 9. |
| 9 / 9 | Paragraph [0043] continues; paragraphs [0044]–[0050] begin. Paragraph [0050] continues on page 10. |
| 10 / 10 | Paragraph [0050] continues; paragraphs [0051]–[0053] begin. Paragraph [0053] continues on page 11. |
| 11 / 11 | Paragraph [0053] continues; paragraphs [0054]–[0056] begin. Paragraph [0056] continues on page 12. |
| 12 / 12 | Paragraph [0056] continues; paragraph [0057] begins and continues on page 13. |
| 13 / 13 | Paragraph [0057] continues; paragraphs [0058]–[0059]. |
| 14 / 14 | Paragraphs [0060]–[0063] begin. Paragraph [0063] continues on page 15. |
| 15 / 15 | Paragraph [0063] continues; paragraphs [0064]–[0066] begin. Paragraph [0066] continues on page 16. |
| 16 / 16 | Paragraph [0066] continues; paragraphs [0067]–[0068]. |
| 17 / 17 | Paragraphs [0069]–[0071]. |
| 18 / 18 | Paragraphs [0072]–[0074]. |
| 19 / 19 | Paragraphs [0075]–[0079] begin. Paragraph [0079] continues on page 20. |
| 20 / 20 | Paragraph [0079] continues; paragraphs [0080]–[0082]. |
| 21 / 21 | Paragraphs [0083]–[0085] begin. Paragraph [0085] continues on page 22. |
| 22 / 22 | Paragraph [0085] continues; paragraphs [0086]–[0089] begin. Paragraph [0089] continues on page 23. |
| 23 / 23 | Paragraph [0089] continues; paragraphs [0090]–[0092]. |
| 24 / 24 | Paragraphs [0093]–[0099], [00100], and [00101]. |
| 25 / 25 | Paragraphs [00102]–[00110]. |
| 26 / 26 | Claim 1; claim 2 begins and continues on page 27. |
| 27 / 27 | Claim 2 continues; claims 3–7; claim 8 begins and continues on page 28. |
| 28 / 28 | Claim 8 continues; claim 9; claim 10 begins and continues on page 29. |
| 29 / 29 | Claim 10 continues; signature block dated 12th June, 2025. |
| 30 / 30 | Abstract and drawing labelled FIG. 1. |
| 31 / 31 | Drawing labelled FIG. 2. |

## Claim index

| Printed claim | PDF page(s) | Printed page(s) |
| --- | --- | --- |
| 1 | 26 | 26 |
| 2 | 26–27 | 26–27 |
| 3 | 27 | 27 |
| 4 | 27 | 27 |
| 5 | 27 | 27 |
| 6 | 27 | 27 |
| 7 | 27 | 27 |
| 8 | 27–28 | 27–28 |
| 9 | 28 | 28 |
| 10 | 28–29 | 28–29 |

## Figure inventory

| Figure | Text references | Drawing in supplied PDF |
| --- | --- | --- |
| FIG. 1 | Described in paragraph [0037] on PDF and printed page 7; referenced in paragraph [0049] on page 9 and paragraph [0050] on page 9. | Present on PDF page 30, printed page 30. |
| FIG. 2 | Described in paragraph [0038] on PDF and printed page 7; referenced in paragraph [0049] on page 9 and paragraph [0074] on page 18. | Present on PDF page 31, printed page 31. |
| FIG. 3 | Described in paragraph [0039] on PDF and printed page 7; referenced in paragraph [0049] on page 9 and paragraph [0080] on page 20. | No drawing appears in the supplied 31-page PDF. The specification contains text references only. |
| FIG. 4 | Described in paragraph [0040] on PDF and printed page 7; referenced in paragraph [0049] on page 9 and paragraphs [0088]–[0089] on pages 22–23. | No drawing appears in the supplied 31-page PDF. The specification contains text references only. |

## Date and legal-status limits

The signature block on PDF page 29, printed page 29, says `Dated: 12th June, 2025`. This is the date printed with the patent agent's signature. This inventory does not verify a filing date, publication date, grant status, or legal coverage, and it is not a legal opinion.

## Claim-to-requirement map (SRC05 / #72)

This is an engineering traceability map of the supplied document, checked on
15 October 2026. It paraphrases source text and identifies planned acceptance
work. **A mapped passage is not an implemented capability, a legal claim
construction, or a finding of patent coverage.** The full requirements and
stable task references are in [requirements.md](../requirements.md). Open
scope decisions remain with SRC02 [#14](https://github.com/i-got-this-faa/device-audit/issues/14)
and CAP02 [#138](https://github.com/i-got-this-faa/device-audit/issues/138).

References below use the document's **printed claim and paragraph labels**;
the PDF page and printed page are identical for this file. Claim 1 is the
system sequence; claims 2-7 expressly refer to claim 1. Claim 8 is the method
sequence; claims 9-10 expressly refer to claim 8. A dependent row below records
its additional text, alongside the inherited sequence. Figures 3 and 4 are
text references only; their absent drawings are not evidence.

### Claims 1 and 8: complete sequence

Claim 1 appears on page 26. Claim 8 begins on page 27 and continues on page 28.
Its numbered method steps below correspond to the system functions; this
cross-reference does not collapse either claim into only its last step.

| Source function | Exact printed location and supporting description | Requirement / stable delivery work | Evidence still needed |
| --- | --- | --- | --- |
| Controller with memory communicates with devices and receives performance parameters | Claim 1, p.26; claim 8 step 302, p.27; [0050]-[0056], pp.9-12; [0081], p.20; FIG.1, p.30 | RQ-01/RQ-02; CT01 #15, TEL01 #21, TEL05 #91, TEL06 #92, TEL07 #93, DB02 #83 | Real collectors and authenticated durable ingestion. The loopback fixture and v2 schema supply neither. Device/OS selections remain #14 decisions. |
| AI analysis identifies faults, predicts failures and assigns per-device health | Claim 1, p.26; claim 8 step 304, p.28; [0056]-[0057], pp.11-13; [0082], p.20 | RQ-04; CT02 #16, CT03 #32, ML02 #33, ML04 #35, ML06 #103, ML09 #105, ML10 #106 | Versioned features, trained artifact, baseline comparisons, evaluated prediction/health thresholds and traceable history. The #22 historical HDD study does not qualify general endpoint predictions. |
| Deploy agents with monitoring/analysis roles corresponding to assigned health | Claim 1, p.26; claim 8 step 306, p.28; [0058], p.13; [0083], p.21 | RQ-04/RQ-05; ML03 #34, DIA01 #36, DIA02 #37, DIA03 #38, DIA05 #109 | Health-specific authenticated assignments executing on real endpoints. A permanently running collector alone does not demonstrate health-based role assignment. General executable-agent deployment remains an unmatched embodiment below. |
| Initiate device-local federated learning and aggregate updates into forecast data | Claim 1, p.26; claim 8 step 308, p.28; claim 4, p.27; [0059]-[0061], pp.13-14; [0084], p.21 | RQ-06; FED01 #40, FED02 #42, FED03 #43, FED08 #113, FED09 #114, FED10 #115, FED13 #118 | Two real endpoints train compatible updates; authenticated aggregation, held-out candidate evaluation and forecast provenance. A weighted-average primitive is only a scaffold. |
| Use forecast data to coordinate localized anomaly analysis and diagnostic insights | Claim 1, p.26; claim 8 step 310, p.28; [0063]-[0064], pp.14-15; [0085], pp.21-22 | RQ-05/RQ-06; DIA02 #37, DIA05 #109, DIA06 #110, FED13 #118, FED06 #70 | Evaluated fresh forecast -> deduplicated job -> local diagnostic evidence on two devices; stale/unavailable forecasts must not launch unsupported work. Generic scheduling alone is insufficient. |
| Generate an audit report with device-specific recommendations | Claim 1, p.26; claim 8 step 312, p.28; claim 5, p.27; [0065]-[0066], pp.15-16; [0086], p.22 | RQ-07/RQ-08/RQ-09; AUD01 #45, LIF01 #46, WEB09 #125, WEB11 #131 | Reports grounded in attributable diagnostics, predictions and cost inputs. Repair instructions and recommendations are outputs; executing repair/configuration changes remains excluded. |
| Evaluate carbon footprint, e-waste reduction and projected operational longevity from the audit report | Claim 1, p.26; claim 8 step 314, p.28; [0067]-[0068], p.16; [0087], p.22 | RQ-08; CT08 #78, LIF02 #121, LIF03 #122, WEB09 #125 | Versioned methodology, units, factors, uncertainty and reproducible reference cases. Null outputs cannot be counted as completed sustainability estimates. |

### Claims 2-7, 9 and 10: additional functions

| Printed claim / page(s) | Additional source text (paraphrase) and description references | Requirement / stable delivery work | Reconciliation / remaining acceptance |
| --- | --- | --- | --- |
| 2 / pp.26-27 | Normalize and filter noise; extract statistical/temporal features; use a stored ML model for faults; compare historical baselines for failure prediction; use fault number, type, recurrence and predicted failures for health. [0029], p.6; [0044], p.9; [0056]-[0057], pp.11-13 | RQ-04; CT03 #32, ML07 #102, ML09 #105, ML10 #106, ML04 #35, ML06 #103 | Controller preprocessing and history comparison are explicit work, in addition to endpoint inference. Freeze windows, missing-value policy and health thresholds; a wire health enum is insufficient. |
| 3 / p.27 | Derive performance trends and usage patterns from diagnostics to determine an expected end-of-lifecycle condition. [0030], p.6; [0045], p.9; [0068], p.16 | RQ-08; CT08 #78, LIF03 #122, LIF01 #46 | Versioned longevity methodology with explicit time units, uncertainty and sparse/contradictory-history cases; a short forecast horizon is not a remaining-life estimate. |
| 4 / p.27 | Train prediction models locally on each device and send model updates to the controller for aggregation. [0031], p.6; [0046], p.9; [0059]-[0061], pp.13-14 | RQ-06; FED02 #42, FED03 #43, FED08 #113, FED09 #114, FED12 #117 | Device-local training and update validation must be demonstrated; centralized training plus model download does not supply local training. Privacy claims need a separate data-flow/threat review. |
| 5 / p.27 | Audit report contains at least one repair instruction, component upgrade recommendation or device replacement suggestion. [0065], p.15; [00102], p.25 | RQ-08; LIF01 #46, WEB09 #125, WEB11 #131 | Preserve the source's at-least-one alternative; do not silently require every report to recommend all three. No remediation executor is implied by a written recommendation. |
| 6 / p.27 | Associate a device-specific sustainability score from evaluated sustainability metrics. [0032], p.6; [0047], p.9; [0067], p.16 | RQ-08; LIF02 #121, CT08 #78, WEB09 #125 | Define the score's methodology/version, scale, factors and uncertainty. A generic health score does not substitute for a sustainability score. |
| 7 / p.27 | Find frequently failing components across devices from aggregated diagnostic insights and recommend batch maintenance or replacement. [0033], p.6; [0048], p.9; [0069], p.17 | RQ-08; API03 #97, FLEET01 #71, FLEET02 #128, WEB05 #53 | Durable component identity, explicit cohorts/windows/denominators, deduplication and recurrence thresholds. Inventory records alone are not fleet failure analysis; recommendations do not execute maintenance. |
| 9 / p.28 | Method analysis normalizes/filters, extracts statistical/temporal features, detects faults with a stored model, compares historical baselines to predict failures, and assigns health by fault type/count/recurrence. [0082], p.20 | RQ-04; CT03 #32, ML07 #102, ML09 #105, ML10 #106, ML04 #35, ML06 #103 | Same preprocessing/history acceptance boundary as claim 2. Claim 9's final clause lists type/count/recurrence; claim 2 also expressly mentions predicted failures there. Retain that textual difference without treating either as completed. |
| 10 / pp.28-29 | Use diagnostic trends and usage patterns to determine expected end-of-lifecycle. [0068], p.16 | RQ-08; LIF03 #122, LIF01 #46 | The source prints "driving" on p.29, whereas claim 3 prints "derive" on p.27; this map records the wording difference without correcting the source. Method longevity needs the same evidence as claim 3. |

All ten printed claims have a row or a complete sequence above. There is no
unmapped claim number. This does **not** mean all described details have a
selected implementation: the differences and unmatched passages below remain
explicitly unresolved or excluded. Implementation acceptance belongs to the
referenced tasks and the RQ-10 integration/release gates, not to #72.

## Metric and terminology gaps

| Printed reference | Source meaning | Current mismatch and owning work |
| --- | --- | --- |
| [0050], pp.9-10; [0056], pp.11-12; [0081], p.20; [0083], p.21 | Examples include CPU/GPU load, memory use, disk I/O/health, network throughput/latency, battery life/health, temperatures and error evidence. Claims 1/8 say one or more performance parameters; they do not enumerate a mandatory sensor checklist. | CT01 #15's v2 utilization/percent/Celsius/latency fields are a subset. Disk space percent is not disk I/O or disk health; battery charge percent is not battery health or life; latency is not throughput. TEL01 #21/TEL04 #85 must select providers and semantics; CT03 #32 must freeze compatible units/windows/features before consumers use them. No newly invented field or sensor guarantee is selected here. |
| [0056]-[0057], pp.11-13; claims 2/9, pp.26-28 | Statistical and temporal features, normalization, noise filtering and historical fault comparison | CT03 #32, ML07 #102, ML09 #105 and ML10 #106 must record algorithms, windows, null handling and baseline provenance. A raw telemetry snapshot or v2 schema cannot supply these transformations. |
| [0057], pp.12-13 | Example health categories include healthy, warning and critical. | CT02 #16 currently uses healthy/degraded/critical/unknown. ML05 #86/ML04 #35 must define and version any warning-to-degraded interpretation and thresholds; unknown remains an evidence outcome. This map does not silently rename either source or wire values. |
| Claims 1/6/8, pp.26-28; [0067]-[0071], pp.16-17 | Carbon footprint, e-waste reduction, device sustainability score and longevity | The source does not supply a calibrated formula, units, factors, score scale or prediction horizon. LIF02 #121/LIF03 #122 must establish and validate them. The illustrative savings example in [0071] is not a measured factor to reuse as fact. |
| [0059]/[0061], pp.13-14; [0084], p.21, alongside claim 1, p.26 | Federated training exchanges updates instead of raw training data, while the system separately receives performance parameters. | FED12 #117 must distinguish telemetry/evidence ingestion from training/update data, document minimization and update leakage, and reconcile the scope of raw-data statements. No claim that all raw evidence stays local or that federated learning guarantees privacy is made. |

## Broader embodiments, unmatched passages and retained exclusions

"Mapped" means planned work exists; "blocked" means a source/product choice
or an exact acceptance boundary is still missing. "Excluded" preserves the
current handoff boundary. These are engineering dispositions, not statements
about the legal effect of a passage. SRC02 #14 owns immediate platform and
conditional-scope choices; CAP02 #138 owns the later complete disposition and
any approved, owned, dependency-linked rebaseline. Reading an embodiment does
not authorize silently expanding the 150-issue release plan.

| Source passage | Disposition against the current plan | Decision / evidence owner |
| --- | --- | --- |
| [0050], pp.9-10: desktops, laptops, servers, thin clients, tablets, mobile and edge devices | Blocked beyond individually approved targets. The source supplies examples, not selected OS/version/hardware combinations. One Windows development laptop does not qualify all device classes. | SRC02 #14; TST06 #61 and CAP01 #58 for measured qualification. |
| [0017], p.4; [00104], p.25; abstract, p.30: hierarchical controller deployment | Unmatched deployment topology. Device/group/network/enterprise dashboard hierarchy is planned but does not implement a hierarchy of controllers. No subordinate-controller protocol or failover boundary is selected. | SRC03 #73 and CAP02 #138; an expansion needs an owned rebaseline. |
| [0058], p.13; [0060], p.14; [00100]-[00101], p.24: update inference logic/baselines and withdraw/replace agents | Model promotion/rollback and typed job cancellation are mapped subsets (FED10 #115, FED11 #116, DIA04 #108, DIA06 #110). General agent-binary replacement/redeployment based on device health remains unmatched. Controlled endpoint release upgrades (PKG03 #136) are not arbitrary agent deployment. | SRC02 #14/CAP02 #138 must settle any broader lifecycle mechanism; package rollout and unrestricted execution remain excluded. |
| [0062], p.14; [0077], p.19; [0079], pp.19-20; FIG.2 stage 208, p.31: OS tuning, throttling and self-repair | Conflicts with read-only collection/diagnostics. Automatic remediation and device configuration changes remain excluded. Claim 5's report instructions can be mapped without executing them. | SRC02 #14/CAP02 #138 record the conflict; DIA01 #36/DIA04 #108 enforce the bounded diagnostic boundary. |
| [0064], p.15; [0075]-[0076], p.19; FIG.2 stages 204/206, p.31: tinyML, reinforcement learning, hybrid transformer/Bayesian/graph models and KRA optimization | Specific algorithms and KRA optimization are unmatched selections, not required technology choices in claims 1-10. Bespoke evaluated models and bounded workflows are selected; no LLM-per-device or specific framework follows from these examples. | ML05 #86, ML06 #103, SRC02 #14/CAP02 #138; no new model architecture selected here. |
| [0066], pp.15-16; [0076], p.19: explainable output and LIME/SHAP examples | WEB03 #39/ML06 #103 can retain inspectable model/evidence explanations. Specific attribution algorithms and generated natural-language explanation machinery are unselected. An optional handoff LLM is not a dependency of prediction or learning. | ML06 #103 and CAP02 #138; require evaluated explanation provenance before an explainability claim. |
| [0070], p.17: team/department scoring, patch-delay penalties and gamification | Unmatched. Device health and sustainability scores do not implement staff/team scoring or reward mechanics. This map adds neither behavior tracking nor patch deployment. | CAP02 #138; no delivery task selected. |
| [0071], p.17: refurbishment vendors, secondary markets and disposal marketplace | Unmatched integration. LIF01 #46/LIF02 #121 cover evidence-backed lifecycle analysis, not vendor recommendations, transactions or a marketplace adapter. | SRC02 #14/CAP02 #138; no vendor, adapter or permissions selected. |
| [0022], p.4; [0078], p.19; [00109], p.25; FIG.2 stage 210, p.31: enterprise asset-system integration | Blocked pending product selection. API03 #97 inventory and WEB05 #53 views are mapped internal subsets, not an external asset-system adapter. This is description/figure material, not an explicit clause of claims 1-10. | SRC02 #14/CAP02 #138; select/exclude an adapter and rebaseline before implementation. |
| [0008], p.3; [0024]-[0026], p.4; [0072]-[0073], p.18: hierarchical dashboards and on-demand reports | Mapped planned RQ-09 work: API03 #97, WEB05 #53, WEB09 #125 and WEB11 #131. Dynamic views require actual persisted evidence and authorization. | RQ-09 tasks plus CAP01 #58; not completed by schemas or fixtures. |
| [0078], p.19; FIG.2 stage 210, p.31: blockchain audit logs and AI cybersecurity | RQ-07 chain commitments are selected by the explicit handoff and have supporting description here; claims 1-10 do not expressly specify blockchain or smart contracts. Broad AI cybersecurity is unmatched beyond the RQ-02/RQ-07 trust boundaries. | CHAIN01 #47, AUD03 #120, CHAIN06 #127, SRC02 #14/CAP02 #138. No raw logs/device identifiers on-chain; integrity does not establish sensor truth. |
| [0051], p.10; [0074], p.18; [0078], p.19; FIG.2, p.31: networks, endpoint metrics and enterprise/security layers | No independent observer, network-probe source or observer trust boundary is defined by these passages. RQ-03 mesh transport and endpoint network metrics are mapped; independent network observation remains blocked, not inferred. | SRC02 #14/CAP02 #138 must select/exclude an observer explicitly; no scanner added. |
| Retained handoff exclusions: Jev, Shepherd configuration management, Nix build workers, MDM, package deployment and unrestricted shell agents | Remain excluded. Claims 1-10 do not name these mechanisms. The source's agent/workflow language does not override those product boundaries. Read-only analysis and signed model rollout do not authorize arbitrary software rollout. | [decisions.md](../decisions.md), SRC02 #14 and CAP02 #138; no unapproved scope change. |

The printed source contains no release-wide accuracy target, sensor sampling
cadence, resource budget, lifecycle formula, chain choice, deployment OS matrix
or general independent-observer specification. Existing ML05 #86, TEL04 #85,
TEL08 #94, LIF02 #121, LIF03 #122, CHAIN01 #47 and SRC02 #14 own these choices.
Missing numeric policies are not filled in from examples or fixture defaults.

## Rechecking this reconciliation

Windows source checks used on 15 October 2026:

```powershell
Get-FileHash -Algorithm SHA256 C:/Users/radhe/Downloads/patent.pdf
(Get-Item C:/Users/radhe/Downloads/patent.pdf).Length
python -c "from pypdf import PdfReader; r=PdfReader('C:/Users/radhe/Downloads/patent.pdf'); print(len(r.pages)); print('\n'.join(p.extract_text() for p in r.pages[25:29]))"
pdftoppm -f 26 -l 31 -r 110 -png C:/Users/radhe/Downloads/patent.pdf patent-review
```

Use an environment with `pypdf` and Poppler available. Read the entire claim
continuations on pp.26-29 and the referenced description paragraphs, and
compare the available figures visually. The image filenames are local review
outputs, not repository artifacts. Check stable task keys against the linked
issue bodies, not just titles. Review must distinguish the source's wording,
the planned requirements, exclusions, unresolved decisions and actual runtime
evidence. The map intentionally makes no implementation or legal-coverage
claim; it does not approve the remaining SRC02/CAP02 product decisions.

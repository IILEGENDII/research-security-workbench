# Evidence and assessment schema 1

A newly initialized private workspace contains workspace.json, the original policy.json, evidence and assessments. An evidence directory is named with its generated 32-character lowercase hex receipt ID. Its two allowed files are receipt.json and report.json. The workbench uses fixed names and checks both on each assessment.

| Receipt fields | Contract |
| --- | --- |
| schema_version, receipt_id | Integer 1 and the enclosing directory ID |
| policy_digest, policy_raw_sha256, check_id, asset_id | Bind the approved policy and its declared subject |
| tool, tool_version, contract | The pinned check-specific tool, 0.1.0 and adapter discriminator |
| collection, subject_binding | imported or fixture_import with operator_declared, local_capture with local_capture, failed_capture with unverified |
| data_class | synthetic or owner_declared. Fixture imports require synthetic |
| observed_at, imported_at | UTC timestamps with Z or +00:00 and up to six fractional digits. Observation must precede or equal import, and import must precede or equal evaluation |
| report_sha256, report_bytes | Lowercase SHA-256 and exact positive size of the unchanged report bytes |
| exit_code | Upstream code reconciled with the report. A failed attempt with no accepted upstream output records null |
| capture | Present only for local_capture. Contains started_at, ended_at, elapsed_seconds, executable_sha256, fixed option identifiers and check-specific input digests |

Failed captures store a small workbench failure record under report.json with operation capture_failure and a sanitized reason. A failure record can only produce an inconclusive result. Captures hash input files. The source or dataset digest binds the selected directory path and filesystem identity. It does not represent a tree snapshot. The clock in the standalone fixture demo is explicitly simulated.

The reader bounds policy bytes at 256 KiB, receipts at 16 KiB, upstream reports at 8 MiB, assessments at 2 MiB, retained receipt count at 200 and bytes read per evidence set at 128 MiB. JSON has a nesting limit of 32, a structural-token budget and bounded strings and numbers. Invalid stored evidence blocks assessment even if another receipt would otherwise satisfy the policy.

The assessment includes the original logical policy definition, both policy digests, evaluation time, profile, required and optional counts, issues and one row per check sorted by ID. Rows preserve scope, thresholds, evidence identities, collection method, upstream operation, age, trusted/declared status, findings, reason codes and next action. Latest observation wins. Equal latest observations are ambiguous. Evidence from a different snapshot cannot silently satisfy both backup and recovery requirements for one asset. Optional absence is reported separately. The final exit gives blocking uncertainty precedence over findings.

A saved assessment includes assessment.txt and assessment.json, published under a fresh ID. Comparison validates the saved summaries and links both input document digests. It checks logical policy identity before reporting transitions, changes in scope or evidence and elapsed age. Use the original workspace to verify raw evidence. A comparison between two exported JSON files cannot authenticate their producer.

[Receipt verifier](../src/research_workbench/evidence.py) · [Assessment and comparison](../src/research_workbench/assessment.py)

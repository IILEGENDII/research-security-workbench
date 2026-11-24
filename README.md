# Research Workstation Security Workbench

Before moving scientific data, a researcher can check whether the relevant source review, data comparison and recovery evidence are current and refer to the intended assets. `research-security` keeps the original local JSON reports, checks their internal consistency and evaluates them against an explicit policy. Every result identifies its subject, scope, collection method and remaining gaps.

Install the release wheel in a trusted Python 3.11+ virtual environment, or run `python -m pip install .` from a reviewed checkout. The core uses the standard library. Each upstream tool is a separate installation.

## Try the offline demonstration

Choose a **new** directory under a private, physical local directory outside every repository. The following paths are placeholders.

```sh
research-security demo --workspace /absolute/private/demo
research-security evidence --workspace /absolute/private/demo
research-security assess --workspace /absolute/private/demo --format text
research-security compare --before /absolute/private/demo/assessments/FIRST_ID/assessment.json --after /absolute/private/demo/assessments/LAST_ID/assessment.json
```

On Windows use an absolute local path such as `C:\PrivateLab\demo` with a private parent you control. The demo prints its three assessment IDs and replays a named historical clock. Its successive synthetic assessments exit 0, 1 and 2. An ordinary `assess` uses the current time. All demo receipts are labeled `fixture_import`. The independent-digest restore success in the demo is a constructed control. The published ordinary restore sample reports no independent digest.

| Evidence | What a satisfactory result means |
| --- | --- |
| sci-security scan | At least one Python file was analyzed, with no scan errors or findings at the policy severity |
| research-integrity verify | A nonempty inventory matched the selected authenticated signed baseline |
| research-recovery audit | The selected snapshot meets the age limit and the repository check meets the requested read scope |
| research-recovery restore | Pinned recovery executed and met the declared verification requirement. Planning cannot supply this evidence |
| scientific-fuzz campaign | The specified bundled parser completed enough synthetic attempts with consistent controls and outcomes |
| science-supplychain audit | Current complete evidence covers the declared PyPI inventory within the policy’s accepted replay assurance |

Imports bind an operator declaration to exact report bytes. A local capture also binds a reviewed command, interval, exit code and input identities. Workstation policies require local captures for satisfaction. Backup and restore therefore remain unverified for a workstation in this version. A synthetic parser campaign is supplemental. A report hash supplies a later byte comparison. Producer identity requires separate controls.

Assessment exit 0 means all required checks are satisfied in the stated scope. Exit 1 means at least one required finding. Exit 2 means a blocking gap or invalid input. Findings remain visible when exit 2 takes precedence. Comparison exits 0 for unchanged, 1 for changes and 2 for incompatible policy or invalid input.

[Operator guide](docs/operator-guide.md) · [Pinned upstream contracts](docs/integration-contracts.md) · [Policy](docs/policy-format.md) · [Evidence](docs/evidence-format.md) · [Migration and recovery](docs/migration-runbook.md) · [Threat model](docs/threat-model.md) · [Limitations](docs/limitations.md) · [Measured evaluation](docs/evaluation.md) · [Real integration commands](CONTRIBUTING.md)

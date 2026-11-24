# Local operation

Create a virtual environment from a trusted interpreter and install the verified distribution. Verify release bytes against a digest obtained through a trusted channel. Install optional collector packages from the exact commits in integration-contracts.md into that same environment. Use standard wheel installations for the upstreams. The workbench checks package version and normalized hashes of their Python source files before launch. The interpreter, site initialization, compiled bytecode and transitive libraries belong to the trusted installation.

Use explicit, owner-controlled directories. Select a new workspace outside datasets, backup repositories, restore trees and source repositories. The parent must already exist. Restrict its ACL to the operator on Windows. Set the policy's profile, required checks and thresholds before collecting. An approved local path is an operator decision. Directory ownership checks cannot establish legal permission or detect every network mount.

```sh
research-security init --workspace /absolute/private/workbench --policy /absolute/control/policy.json
research-security import --workspace /absolute/private/workbench --check source-review --report /absolute/reports/scan.json --tool-version 0.1.0 --observed-at 2026-11-24T07:00:00Z --exit-code 0 --data-class synthetic
research-security collect --workspace /absolute/private/workbench --check source-review --source /absolute/synthetic/source --authorize-local --data-class synthetic
research-security collect --workspace /absolute/private/workbench --check dataset-match --dataset /absolute/synthetic/data --manifest /absolute/control/manifest.json --public-key /absolute/trusted/public.pem --authorize-local --data-class synthetic
research-security collect --workspace /absolute/private/workbench --check dependency-audit --inventory /absolute/synthetic/inventory.json --advisory-evidence /absolute/synthetic/evidence.json --authorize-local --data-class synthetic
research-security assess --workspace /absolute/private/workbench --save --format text
```

Replace the illustrative timestamp with the actual observation time. Import source reports from scans run with `--fail-on low`. The workbench reapplies the policy severity to the full finding list. The import exit code describes admission. The stored upstream exit code has its original meaning, including 3 for signature failure. Collection returns the upstream exit when it produced a verified receipt. Failure to collect or validate produces exit 2 with a sanitized reason.

A local capture selects the fixed installed module for the check. The launcher invokes the active interpreter in isolated mode. No CLI accepts an executable path, command string, extra flag, backup password or signing key. The three command templates appear in the receipt as option identifiers. The child receives minimal Windows system paths where necessary. Its stderr is bounded and discarded. The default wall limit is 90 seconds, standard output is limited to 8 MiB and standard error to 64 KiB.

Backups and restores are import-only. Outside the workbench, an operator can perform a separately authorized backup audit. A full check reads packs and restic may briefly create lock files. Arrange sufficient I/O budget and use an independently verified engine. Recovery requires a distinct empty destination and separate operator approval. A plan alone leaves recoverability unverified. The ordinary upstream recovery report lacks an independently authenticated digest baseline.

Use `evidence` to check receipt metadata and raw hashes. Direct reports to stdout or an unused .json or .txt path outside protected inputs. Protect raw reports, whose upstream file names can identify private assets. Keep prior assessments for comparison. Investigate a failed admission or interrupted write before relying on earlier evidence. Preserve an interrupted workspace and use a fresh one with independently retained original reports if recovery is needed.

# Policy schema 1

A UTF-8 object has exactly five properties. `schema_version` is integer 1. `policy_id`, asset IDs and check IDs match `[a-z][a-z0-9-]{0,47}`. `profile` is synthetic or workstation. `assets` lists at most 100 objects with id and kind. `checks` lists up to 200 objects. IDs are unique within their respective lists. Every check names an existing asset of the matching kind. At least one check must be required.

Each check has id, asset, type, required (a JSON boolean) and max_age_hours (integer 1 through 8760), plus exactly the fields shown below. Unknown keys fail validation. Paths and executable selection are outside the policy.

| Type | Asset kind | Additional required fields |
| --- | --- | --- |
| source_scan | source | min_severity is low, medium or high |
| signed_integrity | dataset | None |
| backup_audit | backup | min_data_scope is structure, subset or full. max_snapshot_age_hours is 1 through 8760 |
| restore_test | backup | require_independent_digest is boolean |
| dependency_audit | dependencies | allow_reviewed_offline_evidence is boolean |
| fuzz_campaign | parser-tests | target is grid, table or metadata. min_attempts is 1 through 10,000 |

The raw SHA-256 covers the supplied bytes including line endings. For logical identity the implementation sorts both lists by ID, sorts JSON object keys, uses compact ASCII-escaped JSON with one trailing LF, and hashes those bytes. A whitespace-only change produces the same logical policy. An initialized workspace also requires the original raw digest. Start a new workspace to change policy.

[Complete synthetic example](../examples/policy.json) · [Validation code](../src/research_workbench/policy.py)

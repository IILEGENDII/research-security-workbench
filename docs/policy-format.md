# Policy schema 1

Required fields are schema_version, policy_id, profile, assets and checks. Assets bind a unique ID to a kind. Checks bind a unique ID to an asset, a type, required status, freshness hours and options specific to that type. Both raw SHA-256 and the digest of the normalized policy are retained. See examples/policy.json.

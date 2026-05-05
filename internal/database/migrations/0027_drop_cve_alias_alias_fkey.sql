-- +goose Up
-- Drop the FK constraint that requires every alias to exist as a cve row.
-- GHSA IDs are aliases, not CVEs, so they should not be required to have
-- their own cve row. Only canonical_cve_id needs to reference cve(cve_id).
ALTER TABLE cve_alias
    DROP CONSTRAINT IF EXISTS cve_alias_alias_fkey;

-- +goose Down
ALTER TABLE cve_alias
    ADD CONSTRAINT cve_alias_alias_fkey
        FOREIGN KEY (alias)
            REFERENCES cve (cve_id)
            ON DELETE CASCADE;

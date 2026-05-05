-- +goose Up
-- Drop the FK constraint that requires every alias to exist as a cve row.
-- GHSA IDs are aliases, not CVEs, so they should not be required to have
-- their own cve row. Only canonical_cve_id needs to reference cve(cve_id).
ALTER TABLE cve_alias
    DROP CONSTRAINT IF EXISTS cve_alias_alias_fkey;

-- +goose Down
-- Remove any alias rows whose alias value has no corresponding cve row —
-- these rows were allowed by the Up migration but would violate the FK
-- being re-added here, causing the rollback to fail.
DELETE FROM cve_alias
WHERE alias NOT IN (SELECT cve_id FROM cve);

ALTER TABLE cve_alias
    ADD CONSTRAINT cve_alias_alias_fkey
        FOREIGN KEY (alias)
            REFERENCES cve (cve_id)
            ON DELETE CASCADE;

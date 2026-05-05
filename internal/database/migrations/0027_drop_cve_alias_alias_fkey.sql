-- +goose Up
-- Drop the FK constraint that requires every alias to exist as a cve row.
-- GHSA IDs are aliases, not CVEs, so they should not be required to have
-- their own cve row. Only canonical_cve_id needs to reference cve(cve_id).
ALTER TABLE cve_alias
    DROP CONSTRAINT IF EXISTS cve_alias_alias_fkey;

-- +goose Down
-- Intentionally delete alias rows whose alias value has no corresponding
-- cve row. These rows are valid after the Up migration (GHSA aliases without
-- a cve row) but would violate cve_alias_alias_fkey being re-added below.
-- This data loss is acceptable on rollback — the rows will be re-created on
-- the next resync once the Up migration is re-applied.
DELETE FROM cve_alias
WHERE alias NOT IN (SELECT cve_id FROM cve);

ALTER TABLE cve_alias
    ADD CONSTRAINT cve_alias_alias_fkey
        FOREIGN KEY (alias)
            REFERENCES cve (cve_id)
            ON DELETE CASCADE;

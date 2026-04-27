-- +goose Up
-- The alias column in cve_alias holds GHSA IDs and other non-CVE identifiers
-- (e.g. "GHSA-25qh-j22f-pwp8"). These will never exist as rows in the cve table
-- because the cve table only stores CVE IDs. The FK was wrong by design and causes
-- every resync cycle to fail with SQLSTATE 23503 when inserting alias rows.
-- The canonical_cve_id FK is correct and is kept.
ALTER TABLE cve_alias
    DROP CONSTRAINT IF EXISTS cve_alias_alias_fkey;

-- +goose Down
ALTER TABLE cve_alias
    ADD CONSTRAINT cve_alias_alias_fkey
    FOREIGN KEY (alias) REFERENCES cve(cve_id) ON DELETE CASCADE;

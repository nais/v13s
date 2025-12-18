-- +goose Up
-- 1. Create table without constraints for fastest bulk load
CREATE TABLE IF NOT EXISTS cve_alias(
    alias TEXT NOT NULL,
    canonical_cve_id TEXT NOT NULL
);

-- 2. Bulk backfill from cve.refs
--    - refs JSON is assumed to be like: {"CVE-2025-11226": "GHSA-25qh-j22f-pwp8"}
--    - key (owner cve_id) = canonical CVE
--    - value (r.v) = alias (GHSA or other alt ID)
--    we only keep rows where BOTH alias and canonical exist in cve
INSERT INTO cve_alias(
    alias,
    canonical_cve_id)
SELECT DISTINCT
    r.value AS alias, -- alias (e.g. GHSA-…)
    r.key AS canonical_cve_id -- canonical CVE (from JSON key)
FROM
    cve canonical
    CROSS JOIN LATERAL jsonb_each_text(canonical.refs) AS r(key,
        value)
    JOIN cve alias_cve ON alias_cve.cve_id = r.value -- alias exists as a cve row
    JOIN cve canonical_cve ON canonical_cve.cve_id = r.key -- canonical exists as a cve row
ON CONFLICT
    DO NOTHING;

ALTER TABLE cve_alias
    ADD CONSTRAINT cve_alias_pkey PRIMARY KEY (alias);

ALTER TABLE cve_alias
    ADD CONSTRAINT cve_alias_alias_fkey FOREIGN KEY (alias) REFERENCES cve(cve_id) ON DELETE CASCADE;

ALTER TABLE cve_alias
    ADD CONSTRAINT cve_alias_canonical_fkey FOREIGN KEY (canonical_cve_id) REFERENCES cve(cve_id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS cve_alias_canonical_idx ON cve_alias(canonical_cve_id);

ANALYZE cve_alias;

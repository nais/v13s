-- backfill_suppressed_vulnerabilities_canonical_cve_id.sql
--
-- Run once after deploying the SuppressVulnerability canonicalization change.
--
-- Background
-- ----------
-- SuppressVulnerability now resolves alias CVE IDs to their canonical counterpart
-- before writing to suppressed_vulnerabilities.  Rows inserted by the old code path
-- were keyed by the alias (e.g. "GHSA-…") rather than the canonical ID (e.g. "CVE-…").
-- All read queries join suppressed_vulnerabilities on the canonical ID, so those
-- legacy rows are silently invisible without this backfill.
--
-- What this script does
-- ---------------------
-- 1. For every alias-keyed row that has no canonical counterpart yet:
--      INSERT a new row under the canonical ID, copying the suppression state.
-- 2. For every alias-keyed row where a canonical row already exists but the
--    alias row is newer:
--      UPDATE the canonical row to reflect the more recent suppression state.
--
-- Alias-keyed rows are intentionally left in place — both rows are kept so that
-- nothing is silently lost if something external still references the alias.
--
-- Safety
-- ------
-- • Runs inside a single transaction; rolls back automatically on any error.
-- • Safe to re-run: step 1 uses INSERT … ON CONFLICT DO NOTHING so duplicate
--   inserts are ignored; step 2 is a no-op when canonical is already up to date.

BEGIN;

-- ── Step 1 ────────────────────────────────────────────────────────────────────
-- Insert a canonical-keyed copy for every alias-keyed row that has no canonical
-- counterpart yet.
INSERT INTO suppressed_vulnerabilities
    (image_name, package, cve_id, suppressed, suppressed_by, reason, reason_text, updated_at)
SELECT
    sv.image_name,
    sv.package,
    ca.canonical_cve_id,
    sv.suppressed,
    sv.suppressed_by,
    sv.reason,
    sv.reason_text,
    sv.updated_at
FROM suppressed_vulnerabilities sv
JOIN cve_alias ca ON sv.cve_id = ca.alias
ON CONFLICT ON CONSTRAINT image_name_package_cve_id DO NOTHING;

-- ── Step 2 ────────────────────────────────────────────────────────────────────
-- Where a canonical row already existed before step 1 (ON CONFLICT skipped it),
-- update it if the alias row carries a more recent suppression state.
WITH newer_alias AS (
    SELECT
        canonical.id AS canonical_id,
        alias_row.suppressed,
        alias_row.suppressed_by,
        alias_row.reason,
        alias_row.reason_text,
        alias_row.updated_at
    FROM suppressed_vulnerabilities alias_row
    JOIN cve_alias ca ON alias_row.cve_id = ca.alias
    JOIN suppressed_vulnerabilities canonical
      ON canonical.image_name = alias_row.image_name
     AND canonical.package    = alias_row.package
     AND canonical.cve_id     = ca.canonical_cve_id
    WHERE alias_row.updated_at > canonical.updated_at
)
UPDATE suppressed_vulnerabilities sv
SET
    suppressed    = na.suppressed,
    suppressed_by = na.suppressed_by,
    reason        = na.reason,
    reason_text   = na.reason_text,
    updated_at    = na.updated_at
FROM newer_alias na
WHERE sv.id = na.canonical_id;

COMMIT;


-- rekey-suppressed-aliases.sql
--
-- Purpose: find alias-keyed suppressed_vulnerabilities rows that are missing
-- a corresponding canonical-keyed row. After the alias-aware suppression join
-- fix ships, both the alias row AND the canonical row must exist so that
-- suppression is found regardless of which cve_id the join resolves to.
--
-- Usage (dry run, default):
--   psql $DATABASE_URL -f scripts/rekey-suppressed-aliases.sql
--
-- The script is SELECT-only by default. The INSERT at the bottom is commented
-- out. Review the dry-run output, then uncomment and re-run to apply.
--
-- Safe to run multiple times (ON CONFLICT DO NOTHING).
-- ============================================================
-- DRY RUN: alias suppress rows that are missing a canonical row
--
-- These are the rows where a canonical suppress record needs to
-- be inserted. Rows where canonical_row_already_exists = true
-- are already in the correct shape and need no action.
-- ============================================================
SELECT
    sv.image_name,
    sv.package,
    sv.cve_id AS alias_cve_id,
    ca.canonical_cve_id,
    sv.suppressed,
    sv.suppressed_by,
    sv.reason,
    sv.reason_text,
    sv.updated_at,
    EXISTS (
        SELECT
            1
        FROM
            suppressed_vulnerabilities existing
        WHERE
            existing.image_name = sv.image_name
            AND existing.package = sv.package
            AND existing.cve_id = ca.canonical_cve_id) AS canonical_row_already_exists
FROM
    suppressed_vulnerabilities sv
    JOIN cve_alias ca ON sv.cve_id = ca.alias
WHERE
    NOT EXISTS (
        SELECT
            1
        FROM
            suppressed_vulnerabilities existing
        WHERE
            existing.image_name = sv.image_name
            AND existing.package = sv.package
            AND existing.cve_id = ca.canonical_cve_id)
ORDER BY
    sv.image_name,
    sv.package,
    sv.cve_id;

-- ============================================================
-- APPLY (uncomment after reviewing dry-run output above)
--
-- Inserts the missing canonical suppress row, copying all fields
-- from the alias row. ON CONFLICT DO NOTHING makes it safe to
-- re-run. The alias row is kept as-is.
--
INSERT INTO suppressed_vulnerabilities(
    image_name,
    package,
    cve_id,
    suppressed,
    suppressed_by,
    reason,
    reason_text,
    updated_at)
SELECT
    sv.image_name,
    sv.package,
    ca.canonical_cve_id,
    sv.suppressed,
    sv.suppressed_by,
    sv.reason,
    sv.reason_text,
    sv.updated_at
FROM
    suppressed_vulnerabilities sv
    JOIN cve_alias ca ON sv.cve_id = ca.alias
WHERE
    NOT EXISTS (
        SELECT
            1
        FROM
            suppressed_vulnerabilities existing
        WHERE
            existing.image_name = sv.image_name
            AND existing.package = sv.package
            AND existing.cve_id = ca.canonical_cve_id)
ON CONFLICT ON CONSTRAINT image_name_package_cve_id
    DO NOTHING;

-- ============================================================

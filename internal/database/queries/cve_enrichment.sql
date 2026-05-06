-- name: BulkUpdateKevData :execrows
UPDATE
    cve
SET
    has_kev_entry = TRUE,
    known_ransomware_use = data.known_ransomware_use,
    updated_at = NOW()
FROM (
    SELECT
        unnest(@cve_ids::TEXT[]) AS cve_id,
        unnest(@known_ransomware_use::BOOLEAN[]) AS known_ransomware_use) AS data
WHERE
    cve.cve_id = data.cve_id
    AND (cve.has_kev_entry = FALSE
        OR cve.known_ransomware_use != data.known_ransomware_use);

-- name: GetVulnerabilitiesForOsvEnrichment :many
SELECT DISTINCT
    cve_id,
    package
FROM
    vulnerabilities
WHERE
    package != ''
    AND (cve_id LIKE 'CVE-%'
        OR cve_id LIKE 'GHSA-%')
ORDER BY
    cve_id,
    package;

-- name: BulkClearFixVersions :execrows
WITH input AS (
    SELECT
        unnest(@cve_ids::TEXT[]) AS cve_id,
        unnest(@packages::TEXT[]) AS package
),
LOCKED AS (
    SELECT
        v.id
    FROM
        vulnerabilities v
        JOIN input i ON v.cve_id = i.cve_id
            AND v.package = i.package
    WHERE
        v.fix_version IS NOT NULL
    ORDER BY
        v.cve_id,
        v.package
    FOR UPDATE)
UPDATE
    vulnerabilities
SET
    fix_version = NULL,
    updated_at = NOW()
FROM
    LOCKED
WHERE
    vulnerabilities.id = locked.id;

-- name: BulkUpdateFixVersions :execrows
WITH input AS (
    SELECT
        unnest(@cve_ids::TEXT[]) AS cve_id,
        unnest(@packages::TEXT[]) AS package,
        unnest(@fix_versions::TEXT[]) AS fix_version
),
LOCKED AS (
    SELECT
        v.id,
        i.fix_version
    FROM
        vulnerabilities v
        JOIN input i ON v.cve_id = i.cve_id
            AND v.package = i.package
    WHERE
        v.fix_version IS DISTINCT FROM i.fix_version
    ORDER BY
        v.cve_id,
        v.package
    FOR UPDATE)
UPDATE
    vulnerabilities
SET
    fix_version = locked.fix_version,
    updated_at = NOW()
FROM
    LOCKED
WHERE
    vulnerabilities.id = locked.id;

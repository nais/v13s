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
UPDATE
    vulnerabilities
SET
    fix_version = NULL,
    updated_at = NOW()
FROM (
    SELECT
        unnest(@cve_ids::TEXT[]) AS cve_id,
        unnest(@packages::TEXT[]) AS package) AS data
WHERE
    vulnerabilities.cve_id = data.cve_id
    AND vulnerabilities.package = data.package
    AND vulnerabilities.fix_version IS NOT NULL;

-- name: BulkUpdateFixVersions :execrows
UPDATE
    vulnerabilities
SET
    fix_version = data.fix_version,
    updated_at = NOW()
FROM (
    SELECT
        unnest(@cve_ids::TEXT[]) AS cve_id,
        unnest(@packages::TEXT[]) AS package,
        unnest(@fix_versions::TEXT[]) AS fix_version) AS data
WHERE
    vulnerabilities.cve_id = data.cve_id
    AND vulnerabilities.package = data.package
    AND (vulnerabilities.fix_version IS NULL
        OR vulnerabilities.fix_version != data.fix_version);

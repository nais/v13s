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
SELECT
    id,
    cve_id,
    package
FROM
    vulnerabilities
WHERE
    package != ''
    AND (cve_id LIKE 'CVE-%'
        OR cve_id LIKE 'GHSA-%')
ORDER BY
    id;

-- name: BulkUpdateFixVersions :execrows
UPDATE
    vulnerabilities
SET
    fix_version = data.fix_version,
    updated_at = NOW()
FROM (
    SELECT
        unnest(@vulnerability_ids::UUID[]) AS id,
        unnest(@fix_versions::TEXT[]) AS fix_version) AS data
WHERE
    vulnerabilities.id = data.id
    AND vulnerabilities.fix_version IS DISTINCT FROM data.fix_version;

-- name: UpdateCvePriority :exec
UPDATE
    cve
SET
    priority = CASE WHEN has_kev_entry = TRUE THEN
        1
    WHEN known_ransomware_use = TRUE
        OR epss_percentile >= 0.90 THEN
        2
    WHEN severity IN (0, 1)
        AND epss_percentile >= 0.50 THEN
        3
    ELSE
        4
    END
WHERE
    priority IS DISTINCT FROM CASE WHEN has_kev_entry = TRUE THEN
        1
    WHEN known_ransomware_use = TRUE
        OR epss_percentile >= 0.90 THEN
        2
    WHEN severity IN (0, 1)
        AND epss_percentile >= 0.50 THEN
        3
    ELSE
        4
    END;

-- name: BulkClearFixVersions :execrows
UPDATE
    vulnerabilities
SET
    fix_version = NULL,
    updated_at = NOW()
WHERE
    id = ANY (@vulnerability_ids::UUID[])
    AND fix_version IS NOT NULL;

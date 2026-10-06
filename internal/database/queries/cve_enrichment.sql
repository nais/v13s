-- name: UpsertKevSourceEntries :execrows
-- Rows are never deleted (see CONTEXT.md).
INSERT INTO cve_kev_source (cve_id, source, known_ransomware_use)
SELECT
    d.cve_id,
    d.source,
    d.known_ransomware_use
FROM (
    SELECT
        unnest(@cve_ids::TEXT[]) AS cve_id,
        unnest(@sources::TEXT[]) AS source,
        unnest(@known_ransomware_use::BOOLEAN[]) AS known_ransomware_use) AS d
    JOIN cve c ON c.cve_id = d.cve_id
ON CONFLICT (cve_id, source)
    DO UPDATE SET
        known_ransomware_use = EXCLUDED.known_ransomware_use,
        last_seen_at = NOW();

-- name: RefreshCveKevFlags :many
WITH changed AS (
    UPDATE
        cve
    SET
        has_kev_entry = k.has_kev_entry,
        known_ransomware_use = k.known_ransomware_use,
        updated_at = NOW()
    FROM (
        SELECT
            c.cve_id,
            COUNT(s.source) > 0 AS has_kev_entry,
            COALESCE(bool_or(s.known_ransomware_use), FALSE) AS known_ransomware_use
        FROM
            cve c
            LEFT JOIN cve_kev_source s ON s.cve_id = c.cve_id
        GROUP BY
            c.cve_id) AS k
    WHERE
        cve.cve_id = k.cve_id
        AND (cve.has_kev_entry != k.has_kev_entry
            OR cve.known_ransomware_use != k.known_ransomware_use)
    RETURNING
        cve.cve_id
)
SELECT
    cve_id
FROM
    changed
ORDER BY
    cve_id;

-- name: ListUsedImagesForCves :many
SELECT DISTINCT
    v.image_name,
    v.image_tag
FROM
    vulnerabilities v
    LEFT JOIN cve_alias ca ON ca.alias = v.cve_id
WHERE
    COALESCE(ca.canonical_cve_id, v.cve_id) = ANY (@cve_ids::TEXT[])
    AND EXISTS (
        SELECT
            1
        FROM
            workloads w
        WHERE
            w.image_name = v.image_name
            AND w.image_tag = v.image_tag)
ORDER BY
    v.image_name,
    v.image_tag;

-- name: GetVulnerabilitiesForOsvEnrichment :many
-- apk/deb excluded: OSV has no purl-tagged fix data for OS-distro packages.
SELECT DISTINCT
    cve_id,
    package
FROM
    vulnerabilities
WHERE
    cve_id != ''
    AND package != ''
    AND package NOT LIKE 'pkg:apk/%'
    AND package NOT LIKE 'pkg:deb/%'
ORDER BY
    cve_id, package;

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
    AND vulnerabilities.fix_version IS DISTINCT FROM data.fix_version;

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

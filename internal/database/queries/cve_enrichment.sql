-- name: BulkUpdateKevData :execrows
-- When a source failed (complete = false), only add flags and sources.
-- A complete run also clears CVEs that no source lists any more.
WITH data AS (
    SELECT
        unnest(@cve_ids::TEXT[]) AS cve_id,
        unnest(@known_ransomware_use::BOOLEAN[]) AS known_ransomware_use
),
source_pairs AS (
    SELECT
        unnest(@source_cve_ids::TEXT[]) AS cve_id,
        unnest(@source_names::TEXT[]) AS source
),
sources AS (
    SELECT
        cve_id,
        array_agg(source ORDER BY source) AS kev_sources
    FROM
        source_pairs
    GROUP BY
        cve_id
),
merged AS (
    SELECT
        c.cve_id,
        CASE WHEN @complete::BOOLEAN THEN d.known_ransomware_use
            ELSE c.known_ransomware_use OR d.known_ransomware_use
        END AS known_ransomware_use,
        CASE WHEN @complete::BOOLEAN THEN s.kev_sources
            ELSE ARRAY(SELECT DISTINCT x FROM unnest(c.kev_sources || s.kev_sources) AS x ORDER BY x)
        END AS kev_sources
    FROM
        data d
        JOIN sources s ON s.cve_id = d.cve_id
        JOIN cve c ON c.cve_id = d.cve_id
),
stale AS (
    SELECT
        c.cve_id,
        FALSE AS known_ransomware_use,
        '{}'::TEXT[] AS kev_sources
    FROM
        cve c
    WHERE
        @complete::BOOLEAN
        AND (c.has_kev_entry = TRUE
            OR cardinality(c.kev_sources) > 0)
        AND NOT c.cve_id = ANY (@cve_ids::TEXT[])
),
changes AS (
    SELECT
        cve_id,
        TRUE AS has_kev_entry,
        known_ransomware_use,
        kev_sources
    FROM
        merged
    UNION ALL
    SELECT
        cve_id,
        FALSE AS has_kev_entry,
        known_ransomware_use,
        kev_sources
    FROM
        stale
)
UPDATE
    cve
SET
    has_kev_entry = ch.has_kev_entry,
    known_ransomware_use = ch.known_ransomware_use,
    kev_sources = ch.kev_sources,
    updated_at = NOW()
FROM
    changes ch
WHERE
    cve.cve_id = ch.cve_id
    AND (cve.has_kev_entry != ch.has_kev_entry
        OR cve.known_ransomware_use != ch.known_ransomware_use
        OR cve.kev_sources IS DISTINCT FROM ch.kev_sources);

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

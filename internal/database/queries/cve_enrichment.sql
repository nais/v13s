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

-- name: ListCveExplanationCandidates :many
WITH public_inputs AS (
    SELECT
        unnest(@cve_ids::TEXT[]) AS cve_id,
        unnest(@input_hashes::TEXT[]) AS input_hash
)
SELECT
    c.cve_id,
    p.input_hash::TEXT AS input_hash
FROM
    public_inputs p
    JOIN cve c ON c.cve_id = p.cve_id
    LEFT JOIN cve_explanation e ON e.cve_id = c.cve_id
WHERE
    c.has_kev_entry
    AND NOT EXISTS (
        SELECT
            1
        FROM
            cve_alias ca
        WHERE
            ca.alias = c.cve_id)
    AND (e.summary IS NULL
        OR e.prompt_version <> @prompt_version
        OR e.input_hash <> p.input_hash)
    AND EXISTS (
        SELECT
            1
        FROM
            vulnerabilities v
        LEFT JOIN cve_alias ca ON ca.alias = v.cve_id
        JOIN workloads w ON w.image_name = v.image_name
            AND w.image_tag = v.image_tag
        JOIN images i ON i.name = w.image_name
            AND i.tag = w.image_tag
    WHERE
        COALESCE(ca.canonical_cve_id, v.cve_id) = c.cve_id
        AND workload_has_usable_sbom(w.state, i.state))
ORDER BY
    e.attempted_at ASC NULLS FIRST,
    c.cve_id
LIMIT @max_candidates;

-- name: BeginCveExplanationAttempt :exec
INSERT INTO cve_explanation(
    cve_id,
    prompt_version,
    input_hash,
    source_urls)
VALUES (
    @cve_id,
    @prompt_version,
    @input_hash,
    @source_urls)
ON CONFLICT (
    cve_id)
    DO UPDATE SET
        summary = NULL,
        action = NULL,
        model = NULL,
        created_at = NULL,
        prompt_version = EXCLUDED.prompt_version,
        input_hash = EXCLUDED.input_hash,
        source_urls = EXCLUDED.source_urls,
        attempted_at = NOW();

-- name: SaveCveExplanation :execrows
UPDATE
    cve_explanation
SET
    summary = @summary,
    action = @action,
    model = @model,
    created_at = NOW()
WHERE
    cve_id = @cve_id
    AND prompt_version = @prompt_version
    AND input_hash = @input_hash;

-- name: GetCveExplanation :one
SELECT
    summary,
    action,
    model,
    prompt_version,
    source_urls,
    created_at
FROM
    cve_explanation
WHERE
    cve_id = COALESCE((
        SELECT
            canonical_cve_id
        FROM cve_alias
        WHERE
            alias = @cve_id), @cve_id)
    AND prompt_version = @prompt_version
    AND summary IS NOT NULL;

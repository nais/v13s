-- name: CreateSourceRef :exec
INSERT INTO source_refs(
    image_name,
    image_tag,
    source_id,
    source_type)
VALUES (
    @image_name,
    @image_tag,
    @source_id,
    @source_type)
ON CONFLICT
    DO NOTHING;

-- name: GetSourceRef :one
SELECT
    *
FROM
    source_refs
WHERE
    image_name = @image_name
    AND image_tag = @image_tag
    AND source_type = @source_type
ORDER BY
    (source_id,
        source_type) DESC;

;

-- name: DeleteSourceRef :exec
DELETE FROM source_refs
WHERE image_name = @image_name
    AND image_tag = @image_tag
    AND source_type = @source_type;

-- name: ListUnusedSourceRefs :many
SELECT
    sr.*
FROM
    source_refs sr
    JOIN images i ON sr.image_name = i.name
        AND sr.image_tag = i.tag
WHERE
    NOT EXISTS (
        SELECT
            1
        FROM
            workloads w
        WHERE
            w.image_name = i.name
            AND w.image_tag = i.tag)
    AND (sqlc.narg('name')::TEXT IS NULL
        OR i.name = sqlc.narg('name')::TEXT)
ORDER BY
    sr.updated_at DESC;

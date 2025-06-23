-- name: CreateSourceRef :exec
INSERT INTO source_refs(
    image_name,
    image_tag,
    source_id,
    source_type
)
VALUES (
        @image_name,
        @image_tag,
        @source_id,
           @source_type
       ) ON CONFLICT
    DO NOTHING
;

-- name: GetSourceRef :one
SELECT *
FROM source_refs
WHERE image_name = @image_name
  AND image_tag = @image_tag
  AND source_type = @source_type
ORDER BY
    (source_id, source_type) DESC;
;

-- name: DeleteSourceRef :exec
DELETE
FROM source_refs
WHERE image_name = @image_name
  AND image_tag = @image_tag
  AND source_type = @source_type;

-- name: CreateSourceKey :exec
INSERT INTO source_keys(uuid,
                        source,
                        team_name,
                        key)
VALUES (@uuid,
        @source,
        @team_name,
        @key) ON CONFLICT
    DO NOTHING;

-- name: GetSourceKey :one
SELECT *
FROM source_keys
WHERE uuid = @uuid;

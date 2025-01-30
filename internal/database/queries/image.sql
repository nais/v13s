-- name: CreateImage :exec
INSERT INTO
        images (name, tag, metadata)
VALUES
        (@name, @tag, @metadata)
ON CONFLICT DO NOTHING
;

-- name: GetImage :one
SELECT * FROM images WHERE name = @name AND tag = @tag;

-- name: GetImagesScheduledForSync :many
SELECT * FROM images
WHERE
    state = 'initialized'
    OR state = 'resync'
ORDER BY
    updated_at DESC
;

-- name: UpdateImageState :exec
UPDATE images
SET
    state = @state,
    updated_at = NOW()
WHERE name = @name AND tag = @tag
;

-- name: MarkImagesForResync :exec
UPDATE images
SET
    state = 'resync',
    updated_at = NOW()
WHERE updated_at < @threshold_time
;
-- name: CreateImage :exec
INSERT INTO
        images (name, tag, metadata)
VALUES
        (@name, @tag, @metadata)
ON CONFLICT DO NOTHING
;

-- name: GetImage :one
SELECT * FROM images WHERE name = @name AND tag = @tag;

-- name: UpdateImageState :exec
UPDATE images
SET
    state = @state,
    updated_at = NOW()
WHERE name = @name AND tag = @tag
;


-- name: CreateImage :one
INSERT INTO
        images (name, tag, metadata)
VALUES
        (@name, @tag, @metadata)
RETURNING
        *
;

-- name: GetImage :one
SELECT * FROM images WHERE name = @name AND tag = @tag;


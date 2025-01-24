-- name: CreateImage :one
INSERT INTO
        images (name, tag, metadata)
VALUES
        (@name, @tag, @metadata)
RETURNING
        *
;


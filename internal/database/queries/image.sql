-- name: CreateImage :one
INSERT INTO
        images (name, tag)
VALUES
        (@name, @tag)
RETURNING
        *
;


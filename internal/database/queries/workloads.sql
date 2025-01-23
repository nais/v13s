-- name: Create :one
INSERT INTO
    workloads (name, workload_type, namespace, cluster, image_name, image_tag)
VALUES
    (@name, @workload_type, @namespace, @cluster, @image_name, @image_tag)
RETURNING
    *
;

-- name: Update :one
UPDATE workloads
SET
    name = COALESCE(sqlc.narg(name), name),
    workload_type = COALESCE(sqlc.narg(workload_type), workload_type),
    namespace = COALESCE(sqlc.narg(namespace), namespace),
    cluster = COALESCE(sqlc.narg(cluster), cluster),
    image_name = COALESCE(sqlc.narg(image_name), image_name),
    image_tag = COALESCE(sqlc.narg(image_tag), image_tag)
WHERE
    workloads.id = @id
RETURNING
    *
;

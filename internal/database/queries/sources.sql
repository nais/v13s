-- name: CreateSourceRef :exec
INSERT INTO source_refs(
    workload_id,
    source_id,
    source_type
)
VALUES (
           @workload_id,
           @source_id,
           @source_type
       ) ON CONFLICT
    DO NOTHING
;

-- name: ListSourceRefs :many
SELECT *
FROM source_refs
WHERE workload_id = @workload_id
  AND source_type = @source_type
ORDER BY
    (source_id, source_type) DESC;
;

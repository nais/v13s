-- name: CreateImage :exec
INSERT INTO
        images (name, tag, metadata)
VALUES
        (@name, @tag, @metadata)
ON CONFLICT DO NOTHING
;

-- name: UpdateImage :exec
UPDATE images SET
    metadata = @metadata,
    updated_at = NOW()
WHERE name = @name AND tag = @tag
;

-- name: GetImage :one
SELECT * FROM images WHERE name = @name AND tag = @tag;

-- name: GetImagesScheduledForSync :many
SELECT *
FROM images
WHERE ready_for_resync_at IS NOT NULL
  AND ready_for_resync_at <= NOW()
  AND state IN ('initialized', 'resync')
ORDER BY updated_at DESC;

-- name: UpdateImageState :exec
UPDATE images
SET
    state = @state,
    ready_for_resync_at = @ready_for_resync_at,
    updated_at = NOW()
WHERE name = @name AND tag = @tag
;

-- name: BatchUpdateImageState :batchexec
UPDATE images
SET
    state = @state,
    ready_for_resync_at = @ready_for_resync_at,
    updated_at = NOW()
WHERE name = @name AND tag = @tag
;

-- name: MarkImagesAsUntracked :execrows
UPDATE images
SET
    state = 'untracked',
    updated_at = NOW()
WHERE state = ANY(@included_states::image_state[])
    AND updated_at < @threshold_time
;

-- name: MarkUnusedImages :execrows
UPDATE images
SET state      = 'unused',
    updated_at = NOW()
WHERE NOT EXISTS (SELECT 1 FROM workloads WHERE image_name = images.name AND image_tag = images.tag)
  AND images.updated_at < @threshold_time
  AND images.state != 'unused'
  AND images.state != ANY(@excluded_states::image_state[]);

-- name: ListUnusedImages :many
SELECT name, tag
FROM images
WHERE NOT EXISTS (SELECT 1 FROM workloads WHERE image_name = images.name AND image_tag = images.tag)
   AND (sqlc.narg('name')::TEXT IS NULL OR name = sqlc.narg('name')::TEXT)
ORDER BY updated_at;

-- name: MarkImagesForResync :exec
UPDATE images
SET state      = 'resync',
    updated_at = NOW()
FROM workloads w
WHERE images.name = w.image_name
  AND images.tag = w.image_tag
  AND images.updated_at < @threshold_time
  AND images.state != 'resync'
  AND images.state != ANY(@excluded_states::image_state[]);


-- name: UpdateImageSyncStatus :exec
INSERT INTO image_sync_status (image_name, image_tag, status_code, reason, source)
VALUES (@image_name, @image_tag, @status_code, @reason, @source) ON CONFLICT (image_name, image_tag) DO
UPDATE
    SET
        status_code = @status_code,
    reason = @reason,
    updated_at = NOW()
;

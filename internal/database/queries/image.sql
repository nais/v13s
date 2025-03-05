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
SELECT *
FROM images
WHERE state IN ('initialized', 'resync')
ORDER BY updated_at DESC;

-- name: UpdateImageState :exec
UPDATE images
SET
    state = @state,
    updated_at = NOW()
WHERE name = @name AND tag = @tag
;

-- name: BatchUpdateImageState :batchexec
UPDATE images
SET
    state = @state,
    updated_at = NOW()
WHERE name = @name AND tag = @tag
;

-- name: MarkImagesAsUntracked :exec
UPDATE images
SET
    state = 'untracked',
    updated_at = NOW()
WHERE state = ANY(@included_states::image_state[])
;

-- name: MarkImagesForResync :exec
UPDATE images
SET state      = 'resync',
    updated_at = NOW()
WHERE updated_at < @threshold_time
  AND state != 'resync'
  AND state != ANY(@excluded_states::image_state[]);

-- name: UpdateImageSyncStatus :exec
INSERT INTO image_sync_status (image_name, image_tag, status_code, reason, source)
VALUES (@image_name, @image_tag, @status_code, @reason, @source) ON CONFLICT (image_name, image_tag) DO
UPDATE
    SET
        status_code = @status_code,
    reason = @reason,
    updated_at = NOW()
;

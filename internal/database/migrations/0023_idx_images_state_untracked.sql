-- +goose NO TRANSACTION
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block.
-- The "NO TRANSACTION" directive tells goose to run this migration outside
-- of a transaction, which is required for CONCURRENTLY to work correctly.
-- +goose Up
-- Add partial index on images.state for efficient untracked image recovery
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_images_state_untracked ON images(state)
WHERE
    state = 'untracked';

-- +goose Down
DROP INDEX IF EXISTS idx_images_state_untracked;

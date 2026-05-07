-- name: TryAdvisoryLock :one
SELECT
    pg_try_advisory_lock(@key::BIGINT);

-- name: AdvisoryUnlock :one
SELECT
    pg_advisory_unlock(@key::BIGINT);

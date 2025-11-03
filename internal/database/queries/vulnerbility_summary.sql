-- name: BatchUpsertVulnerabilitySummary :batchexec
INSERT INTO vulnerability_summary(image_name,
                                  image_tag,
                                  critical,
                                  high,
                                  medium,
                                  low,
                                  unassigned,
                                  risk_score)
VALUES (@image_name,
        @image_tag,
        @critical,
        @high,
        @medium,
        @low,
        @unassigned,
        @risk_score) ON CONFLICT
ON CONSTRAINT image_name_tag DO
UPDATE
    SET critical = @critical,
    high = @high,
    medium = @medium,
    low = @low,
    unassigned = @unassigned,
    risk_score = @risk_score,
    updated_at = NOW()
;

-- name: CreateVulnerabilitySummary :one
INSERT INTO
    vulnerability_summary (image_name, image_tag, critical, high, medium, low, unassigned, risk_score)
VALUES
    (@image_name, @image_tag, @critical, @high, @medium, @low, @unassigned, @risk_score)
RETURNING
    *
;

-- name: ListVulnerabilitySummaries :many
WITH filtered_workloads AS (
    SELECT *
    FROM workloads w
    WHERE
        (sqlc.narg('cluster')::TEXT IS NULL OR w.cluster = sqlc.narg('cluster')::TEXT)
      AND (sqlc.narg('namespace')::TEXT IS NULL OR w.namespace = sqlc.narg('namespace')::TEXT)
      AND (sqlc.narg('workload_types')::TEXT[] IS NULL OR w.workload_type = ANY(sqlc.narg('workload_types')::TEXT[]))
      AND (sqlc.narg('workload_name')::TEXT IS NULL OR w.name = sqlc.narg('workload_name')::TEXT)
)
   , vulnerability_data AS (
    SELECT
        v.id,
        w.name AS workload_name,
        w.workload_type,
        w.namespace,
        w.cluster,
        w.image_name as current_image_name,
        w.image_tag as current_image_tag,
        v.image_name,
        v.image_tag,
        v.critical,
        v.high,
        v.medium,
        v.low,
        v.unassigned,
        v.risk_score,
        w.created_at AS workload_created_at,
        w.updated_at AS workload_updated_at,
        v.created_at AS summary_created_at,
        v.updated_at AS summary_updated_at,
        CASE WHEN v.image_name IS NOT NULL THEN TRUE ELSE FALSE END AS has_sbom
    FROM filtered_workloads w
             LEFT JOIN vulnerability_summary v
                       ON w.image_name = v.image_name
                           AND (
                              -- If no since join on image_tag, if since is set ignore image_tag
                              CASE WHEN sqlc.narg('since')::TIMESTAMP WITH TIME ZONE IS NULL THEN w.image_tag = v.image_tag ELSE TRUE END
                              )
    WHERE
        (sqlc.narg('image_name')::TEXT IS NULL OR v.image_name = sqlc.narg('image_name')::TEXT)
      AND (sqlc.narg('image_tag')::TEXT IS NULL OR v.image_tag = sqlc.narg('image_tag')::TEXT)
      AND (sqlc.narg('since')::TIMESTAMP WITH TIME ZONE IS NULL OR v.updated_at > sqlc.narg('since')::TIMESTAMP WITH TIME ZONE)
)
SELECT *,
       (SELECT COUNT(*) FROM vulnerability_data) AS total_count
FROM vulnerability_data
ORDER BY
    CASE WHEN sqlc.narg('order_by') = 'workload_asc' THEN workload_name END ASC,
    CASE WHEN sqlc.narg('order_by') = 'workload_desc' THEN workload_name END DESC,
    CASE WHEN sqlc.narg('order_by') = 'namespace_asc' THEN namespace END ASC,
    CASE WHEN sqlc.narg('order_by') = 'namespace_desc' THEN namespace END DESC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_asc' THEN cluster END ASC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_desc' THEN cluster END DESC,
    CASE WHEN sqlc.narg('order_by') = 'critical_asc' THEN COALESCE(critical, 999999) END ASC,
    CASE WHEN sqlc.narg('order_by') = 'critical_desc' THEN COALESCE(critical, -1) END DESC,
    CASE WHEN sqlc.narg('order_by') = 'high_asc' THEN COALESCE(high, 999999) END ASC,
    CASE WHEN sqlc.narg('order_by') = 'high_desc' THEN COALESCE(high, -1) END DESC,
    CASE WHEN sqlc.narg('order_by') = 'medium_asc' THEN COALESCE(medium, 999999) END ASC,
    CASE WHEN sqlc.narg('order_by') = 'medium_desc' THEN COALESCE(medium, -1) END DESC,
    CASE WHEN sqlc.narg('order_by') = 'low_asc' THEN COALESCE(low, 999999) END ASC,
    CASE WHEN sqlc.narg('order_by') = 'low_desc' THEN COALESCE(low, -1) END DESC,
    CASE WHEN sqlc.narg('order_by') = 'unassigned_asc' THEN COALESCE(unassigned, 999999) END ASC,
    CASE WHEN sqlc.narg('order_by') = 'unassigned_desc' THEN COALESCE(unassigned, -1) END DESC,
    CASE WHEN sqlc.narg('order_by') = 'risk_score_asc' THEN COALESCE(risk_score, 999999) END ASC,
    CASE WHEN sqlc.narg('order_by') = 'risk_score_desc' THEN COALESCE(risk_score, -1) END DESC,
    summary_updated_at ASC, id DESC
    LIMIT sqlc.arg('limit')
OFFSET sqlc.arg('offset');

-- name: GetVulnerabilitySummary :one
WITH filtered_workloads AS (
    SELECT w.id, w.image_name, w.image_tag
    FROM workloads w
    WHERE
        (sqlc.narg('cluster')::TEXT IS NULL OR w.cluster = sqlc.narg('cluster')::TEXT)
      AND (sqlc.narg('namespace')::TEXT IS NULL OR w.namespace = sqlc.narg('namespace')::TEXT)
      AND (sqlc.narg('workload_types')::TEXT[] IS NULL OR w.workload_type = ANY(sqlc.narg('workload_types')::TEXT[]))
      AND (sqlc.narg('workload_name')::TEXT IS NULL OR w.name = sqlc.narg('workload_name')::TEXT)
)
SELECT
    CAST(COUNT(DISTINCT fw.id) AS INT4) AS workload_count,
    CAST(COUNT(DISTINCT CASE WHEN v.image_name IS NOT NULL THEN fw.id END) AS INT4) AS workload_with_sbom,
    CAST(COALESCE(SUM(v.critical), 0) AS INT4) AS critical,
    CAST(COALESCE(SUM(v.high), 0) AS INT4) AS high,
    CAST(COALESCE(SUM(v.medium), 0) AS INT4) AS medium,
    CAST(COALESCE(SUM(v.low), 0) AS INT4) AS low,
    CAST(COALESCE(SUM(v.unassigned), 0) AS INT4) AS unassigned,
    CAST(COALESCE(SUM(v.risk_score), 0) AS INT4) AS risk_score,
    MAX(v.updated_at)::timestamptz AS updated_at
FROM filtered_workloads fw
         LEFT JOIN vulnerability_summary v
                   ON fw.image_name = v.image_name AND fw.image_tag = v.image_tag;

-- name: GetVulnerabilitySummaryTimeSeries :many
SELECT
    snapshot_date,
    SUM(workload_count)::INT4 AS workload_count,
    SUM(critical)::INT4 AS critical,
    SUM(high)::INT4 AS high,
    SUM(medium)::INT4 AS medium,
    SUM(low)::INT4 AS low,
    SUM(unassigned)::INT4 AS unassigned,
    SUM(total)::INT4 AS total,
    SUM(risk_score)::INT4 AS risk_score
FROM mv_vuln_summary_daily_by_workload
WHERE snapshot_date >= sqlc.arg('since')::TIMESTAMPTZ
  AND snapshot_date <= CURRENT_DATE
  AND (sqlc.narg('cluster')::TEXT IS NULL OR cluster = sqlc.narg('cluster')::TEXT)
  AND (sqlc.narg('namespace')::TEXT IS NULL OR namespace = sqlc.narg('namespace')::TEXT)
  AND (sqlc.narg('workload_types')::TEXT[] IS NULL OR workload_type = ANY(sqlc.narg('workload_types')::TEXT[]))
  AND (sqlc.narg('workload_name')::TEXT IS NULL OR workload_name = sqlc.narg('workload_name')::TEXT)
GROUP BY snapshot_date
ORDER BY snapshot_date;


-- name: RefreshVulnerabilitySummaryDailyView :exec
REFRESH MATERIALIZED VIEW CONCURRENTLY mv_vuln_summary_daily_by_workload;

-- name: GetVulnerabilitySummaryForImage :one
SELECT * FROM vulnerability_summary
WHERE image_name = @image_name
  AND image_tag = @image_tag;

-- name: GetLastSnapshotDateForVulnerabilitySummary :one
SELECT COALESCE(MAX(snapshot_date), '2025-01-01')::date AS last_snapshot
FROM vuln_daily_by_workload;


-- name: RefreshVulnerabilitySummaryForDate :exec
WITH latest_summary_per_day AS (
    SELECT DISTINCT ON (w.id)
    @date::date AS snapshot_date,
    w.id AS workload_id,
    w.name AS workload_name,
    w.cluster,
    w.namespace,
    w.workload_type,
    COALESCE(vs.critical, 0) AS critical,
    COALESCE(vs.high, 0) AS high,
    COALESCE(vs.medium, 0) AS medium,
    COALESCE(vs.low, 0) AS low,
    COALESCE(vs.unassigned, 0) AS unassigned,
    COALESCE(vs.risk_score, 0) AS risk_score,
    (vs.id IS NOT NULL) AS has_summary
FROM workloads w
    LEFT JOIN vulnerability_summary vs
ON w.image_name = vs.image_name
    AND w.image_tag = vs.image_tag
    AND vs.updated_at::date <= @date::date
ORDER BY w.id, vs.updated_at DESC
    )
INSERT INTO vuln_daily_by_workload (
    snapshot_date,
    workload_id,
    workload_name,
    cluster,
    namespace,
    workload_type,
    critical,
    high,
    medium,
    low,
    unassigned,
    total,
    risk_score,
    has_summary
)
SELECT
    snapshot_date,
    workload_id,
    workload_name,
    cluster,
    namespace,
    workload_type,
    COALESCE(critical, 0)::INT4,
        COALESCE(high, 0)::INT4,
        COALESCE(medium, 0)::INT4,
        COALESCE(low, 0)::INT4,
        COALESCE(unassigned, 0)::INT4,
        (COALESCE(critical, 0) + COALESCE(high, 0) + COALESCE(medium, 0) + COALESCE(low, 0) + COALESCE(unassigned, 0))::INT4,
    COALESCE(risk_score, 0)::INT4,
    has_summary
FROM latest_summary_per_day
    ON CONFLICT (snapshot_date, workload_id) DO UPDATE
                                                    SET
                                                    critical = EXCLUDED.critical,
                                                    high = EXCLUDED.high,
                                                    medium = EXCLUDED.medium,
                                                    low = EXCLUDED.low,
                                                    unassigned = EXCLUDED.unassigned,
                                                    total = EXCLUDED.total,
                                                    risk_score = EXCLUDED.risk_score,
                                                    has_summary = EXCLUDED.has_summary;

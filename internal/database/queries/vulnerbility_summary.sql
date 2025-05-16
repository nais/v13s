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
    CAST(COALESCE(SUM(v.risk_score), 0) AS INT4) AS risk_score
FROM filtered_workloads fw
         LEFT JOIN vulnerability_summary v
                   ON fw.image_name = v.image_name AND fw.image_tag = v.image_tag;

-- newest version
-- name: SummaryTimeseries :many
WITH snapshot_start_date AS (
    SELECT COALESCE(
                   (
                       SELECT MAX(updated_at)::DATE
                       FROM vulnerability_summary
                       WHERE updated_at < sqlc.narg('since')::TIMESTAMPTZ
               ),
        sqlc.narg('since')::DATE
    ) AS start_date
),
-- 1. Generate list of dates from that starting point to today
     date_series AS (
         SELECT generate_series(
                        (SELECT start_date FROM snapshot_start_date),
                        CURRENT_DATE,
                        interval '1 day'
                )::date AS snapshot_date
     ),
-- 2. Join each workload with each date
     all_workloads AS (
         SELECT id AS workload_id, image_name
         FROM workloads w
            WHERE (sqlc.narg('cluster')::TEXT IS NULL OR w.cluster = sqlc.narg('cluster')::TEXT)
              AND (sqlc.narg('namespace')::TEXT IS NULL OR w.namespace = sqlc.narg('namespace')::TEXT)
              AND (sqlc.narg('workload_types')::TEXT[] IS NULL OR w.workload_type = ANY(sqlc.narg('workload_types')::TEXT[]))
              AND (sqlc.narg('workload_name')::TEXT IS NULL OR w.name = sqlc.narg('workload_name')::TEXT)
     ),
     workload_dates AS (
         SELECT w.workload_id, w.image_name, d.snapshot_date
         FROM all_workloads w
                  CROSS JOIN date_series d
     ),
-- 3. For each workload/date, get latest summary up to that date
     latest_summary_per_day AS (
         SELECT DISTINCT ON (wd.workload_id, wd.snapshot_date)
    wd.snapshot_date,
    wd.workload_id,
    vs.critical,
    vs.high,
    vs.medium,
    vs.low,
    vs.unassigned,
    vs.risk_score
FROM workload_dates wd
    LEFT JOIN vulnerability_summary vs
ON wd.image_name = vs.image_name
    AND vs.updated_at::date <= wd.snapshot_date
WHERE vs IS NOT NULL
ORDER BY wd.workload_id, wd.snapshot_date, vs.updated_at DESC
    ),
-- 4. Aggregate totals per day
    daily_aggregate AS (
SELECT
    snapshot_date,
    COUNT(DISTINCT workload_id)::INT4 AS workload_count,
    SUM(critical)::INT4 AS critical,
    SUM(high)::INT4 AS high,
    SUM(medium)::INT4 AS medium,
    SUM(low)::INT4 AS low,
    SUM(unassigned)::INT4 AS unassigned,
    SUM(critical + high + medium + low + unassigned)::INT4 AS total,
    SUM(risk_score)::INT4 AS risk_score
FROM latest_summary_per_day
GROUP BY snapshot_date
    )
-- 5. Final output
SELECT *
FROM daily_aggregate
ORDER BY snapshot_date;


-- name: SummaryTimeseries0 :many
WITH snapshot_start_date AS (
    SELECT COALESCE(
                   (
                       SELECT MAX(updated_at)::DATE
                       FROM vulnerability_summary
                       WHERE updated_at < sqlc.narg('since')::TIMESTAMPTZ
               ),
        sqlc.narg('since')::DATE  -- fallback to 'since' if no earlier summaries
    ) AS start_date
),
-- 1. Create the date range from start date up to today
     date_series AS (
         SELECT generate_series(
                        (SELECT start_date FROM snapshot_start_date),
                        CURRENT_DATE,
                        interval '1 day'
                )::date AS snapshot_date
     ),
-- 2. Get all workloads with image_name (we'll join on image_name)
     workloads AS (
         SELECT id AS workload_id, image_name, name AS workload_name, namespace, cluster
         FROM workloads w
         WHERE (sqlc.narg('cluster')::TEXT IS NULL OR w.cluster = sqlc.narg('cluster')::TEXT)
            AND (sqlc.narg('namespace')::TEXT IS NULL OR w.namespace = sqlc.narg('namespace')::TEXT)
            AND (sqlc.narg('workload_types')::TEXT[] IS NULL OR w.workload_type = ANY(sqlc.narg('workload_types')::TEXT[]))
            AND (sqlc.narg('workload_name')::TEXT IS NULL OR w.name = sqlc.narg('workload_name')::TEXT)
     ),
-- 3. Combine every workload with every day
     workload_dates AS (
         SELECT
             w.workload_id,
             w.image_name,
             w.workload_name,
             w.namespace,
             w.cluster,
             d.snapshot_date
         FROM workloads w
                  CROSS JOIN date_series d
     ),
-- 4. For each workload + day, find the most recent vulnerability summary up to that day
     latest_summary_per_day AS (
         SELECT DISTINCT ON (wd.workload_id, wd.snapshot_date)
    wd.workload_id,
    wd.workload_name,
    wd.namespace,
    wd.cluster,
    wd.snapshot_date,
    vs.critical,
    vs.high,
    vs.medium,
    vs.low,
    vs.unassigned,
    vs.risk_score
FROM workload_dates wd
    LEFT JOIN vulnerability_summary vs
ON wd.image_name = vs.image_name
    AND vs.updated_at::date <= wd.snapshot_date
WHERE vs IS NOT NULL
ORDER BY wd.workload_id, wd.snapshot_date, vs.updated_at DESC
    )
-- 5. Return full time series
SELECT *
FROM latest_summary_per_day
ORDER BY workload_id, snapshot_date;



-- name: ListVulnerabilitySummaryTimeseries :many
WITH filtered_workloads AS (
    SELECT *
    FROM workloads w
    WHERE
        (sqlc.narg('cluster')::TEXT IS NULL OR w.cluster = sqlc.narg('cluster')::TEXT)
      AND (sqlc.narg('namespace')::TEXT IS NULL OR w.namespace = sqlc.narg('namespace')::TEXT)
      AND (sqlc.narg('workload_types')::TEXT[] IS NULL OR w.workload_type = ANY(sqlc.narg('workload_types')::TEXT[]))
      AND (sqlc.narg('workload_name')::TEXT IS NULL OR w.name = sqlc.narg('workload_name')::TEXT)
),
-- New: get most recent summary before `since`
     older_summary AS (
         SELECT DISTINCT ON (image_name)
    *
FROM vulnerability_summary
WHERE sqlc.narg('since')::TIMESTAMPTZ IS NOT NULL
  AND updated_at < sqlc.narg('since')::TIMESTAMPTZ
ORDER BY image_name, updated_at DESC
    ),
-- Get all newer summaries + join to workloads
    recent_summaries AS (
SELECT *
FROM vulnerability_summary
WHERE sqlc.narg('since')::TIMESTAMPTZ IS NULL OR updated_at > sqlc.narg('since')::TIMESTAMPTZ
    ),
-- Combine recent and one older summary per image
    combined_summaries AS (
SELECT * FROM recent_summaries
UNION ALL
SELECT * FROM older_summary
    ),
-- Join with workloads
    vulnerability_data AS (
SELECT
    v.id,
    w.name AS workload_name,
    w.workload_type,
    w.namespace,
    w.cluster,
    w.image_name AS current_image_name,
    w.image_tag AS current_image_tag,
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
    LEFT JOIN combined_summaries v
ON w.image_name = v.image_name
    AND (
    CASE
    WHEN sqlc.narg('since')::TIMESTAMPTZ IS NULL THEN w.image_tag = v.image_tag
    ELSE TRUE
    END
    )
WHERE
    (sqlc.narg('image_name')::TEXT IS NULL OR v.image_name = sqlc.narg('image_name')::TEXT)
  AND (sqlc.narg('image_tag')::TEXT IS NULL OR v.image_tag = sqlc.narg('image_tag')::TEXT)
    )
SELECT *,
       (SELECT COUNT(*) FROM vulnerability_data) AS total_count
FROM vulnerability_data
ORDER BY
    -- your ordering logic here
    summary_updated_at ASC, id DESC;




-- TODO: remove later below
-- name: GetVulnerabilitySummaryTimeSeriesNonCumulative :many
WITH filtered_workloads AS (
    SELECT
        w.image_name,
        w.cluster,
        w.namespace,
        w.workload_type,
        w.name AS workload_name
    FROM workloads w
    WHERE
        (sqlc.narg('cluster')::TEXT IS NULL OR w.cluster = sqlc.narg('cluster')::TEXT)
      AND (sqlc.narg('namespace')::TEXT IS NULL OR w.namespace = sqlc.narg('namespace')::TEXT)
      AND (sqlc.narg('workload_types')::TEXT[] IS NULL OR w.workload_type = ANY(sqlc.narg('workload_types')::TEXT[]))
      AND (sqlc.narg('workload_name')::TEXT IS NULL OR w.name = sqlc.narg('workload_name')::TEXT)
),
     joined AS (
         SELECT
             v.*,
             fw.cluster,
             fw.namespace,
             fw.workload_type,
             fw.workload_name,
             CASE
                 WHEN sqlc.narg('resolution') = 'day' THEN date_trunc('day', v.updated_at)
                 WHEN sqlc.narg('resolution') = 'week' THEN date_trunc('week', v.updated_at)
                 WHEN sqlc.narg('resolution') = 'month' THEN date_trunc('month', v.updated_at)
                 WHEN sqlc.narg('resolution') = 'hour' THEN date_trunc('hour', v.updated_at)
                 ELSE date_trunc('day', v.updated_at) -- default fallback
             END AS bucket_time
         FROM vulnerability_summary v
                  JOIN filtered_workloads fw ON v.image_name = fw.image_name
         WHERE sqlc.narg('since')::timestamptz IS NULL
    OR v.updated_at >= sqlc.narg('since')::timestamptz
    ),
    latest_per_workload_per_bucket AS (
SELECT DISTINCT ON (workload_name, bucket_time)
    bucket_time,
    cluster,
    namespace,
    workload_type,
    critical,
    high,
    medium,
    low,
    unassigned,
    risk_score
FROM joined
ORDER BY workload_name, bucket_time, updated_at DESC
    ),
    grouped AS (
SELECT
    bucket_time,
    COALESCE(CASE WHEN 'cluster' = ANY(sqlc.arg('group_by')::TEXT[]) THEN cluster ELSE NULL END, 'all') AS group_cluster,
    COALESCE(CASE WHEN 'namespace' = ANY(sqlc.arg('group_by')::TEXT[]) THEN namespace ELSE NULL END, 'all') AS group_namespace,
    COALESCE(CASE WHEN 'workload_type' = ANY(sqlc.arg('group_by')::TEXT[]) THEN workload_type ELSE NULL END, 'all') AS group_workload_type,
    critical,
    high,
    medium,
    low,
    unassigned,
    risk_score
FROM latest_per_workload_per_bucket
    )
SELECT
    bucket_time::timestamptz AS bucket_time,
    group_cluster::TEXT AS group_cluster,
    group_namespace::TEXT AS group_namespace,
    group_workload_type::TEXT AS group_workload_type,
    SUM(critical)::INT4 AS critical,
    SUM(high)::INT4 AS high,
    SUM(medium)::INT4 AS medium,
    SUM(low)::INT4 AS low,
    SUM(unassigned)::INT4 AS unassigned,
    SUM(risk_score)::INT4 AS risk_score,
    COUNT(*)::INT4 AS workload_count
FROM grouped
GROUP BY
    bucket_time,
    group_cluster,
    group_namespace,
    group_workload_type
ORDER BY bucket_time;

-- name: GetVulnerabilitySummaryTimeSeries :many
-- Generate the time series calendar
WITH time_buckets AS (
    SELECT date_trunc(
                   CASE
                       WHEN sqlc.arg('resolution')::TEXT = 'hour' THEN 'hour'
                       WHEN sqlc.arg('resolution')::TEXT = 'week' THEN 'week'
                       WHEN sqlc.arg('resolution')::TEXT = 'month' THEN 'month'
                       ELSE 'day'
                       END,
                   dd
           )::timestamptz AS bucket_time
    FROM generate_series(
                 COALESCE(sqlc.arg('since')::timestamptz, now() - interval '30 days'),
                 now(),
                 CASE
                     WHEN sqlc.arg('resolution')::TEXT = 'hour' THEN interval '1 hour'
                     WHEN sqlc.arg('resolution')::TEXT = 'week' THEN interval '1 week'
                     WHEN sqlc.arg('resolution')::TEXT = 'month' THEN interval '1 month'
                     ELSE interval '1 day'
                     END
         ) dd
),
     filtered_workloads AS (
         SELECT
             w.image_name,
             w.cluster,
             w.namespace,
             w.workload_type,
             w.name AS workload_name
         FROM workloads w
         WHERE
             (sqlc.narg('cluster')::TEXT IS NULL OR w.cluster = sqlc.narg('cluster')::TEXT)
           AND (sqlc.narg('namespace')::TEXT IS NULL OR w.namespace = sqlc.narg('namespace')::TEXT)
           AND (sqlc.narg('workload_types')::TEXT[] IS NULL OR w.workload_type = ANY(sqlc.narg('workload_types')::TEXT[]))
           AND (sqlc.narg('workload_name')::TEXT IS NULL OR w.name = sqlc.narg('workload_name')::TEXT)
           AND EXISTS (
             SELECT 1
             FROM vulnerability_summary vs
             WHERE vs.image_name = w.image_name
         )
     ),
     workload_time_matrix AS (
         SELECT
             tb.bucket_time,
             fw.image_name,
             fw.workload_name,
             fw.cluster,
             fw.namespace,
             fw.workload_type
         FROM time_buckets tb
                  CROSS JOIN filtered_workloads fw
     ),
     summarized AS (
         SELECT
             wtm.bucket_time,
             wtm.cluster,
             wtm.namespace,
             wtm.workload_type,
             wtm.workload_name,
             v.critical,
             v.high,
             v.medium,
             v.low,
             v.unassigned,
             v.risk_score,
             v.updated_at
         FROM workload_time_matrix wtm
                  LEFT JOIN vulnerability_summary v
                            ON wtm.image_name = v.image_name
                                AND v.updated_at BETWEEN COALESCE(sqlc.arg('since'), now() - interval '30 days') AND wtm.bucket_time
     ),
     -- pick latest per workload as of that bucket_time
     latest_per_workload_per_bucket AS (
         SELECT DISTINCT ON (workload_name, bucket_time)
    bucket_time,
    cluster,
    namespace,
    workload_type,
    critical,
    high,
    medium,
    low,
    unassigned,
    risk_score
FROM summarized
ORDER BY workload_name, bucket_time, updated_at DESC NULLS LAST
    ),
    grouped AS (
SELECT
    bucket_time,
    COALESCE(CASE WHEN 'cluster' = ANY(sqlc.arg('group_by')::TEXT[]) THEN cluster ELSE NULL END, 'all')::TEXT AS group_cluster,
    COALESCE(CASE WHEN 'namespace' = ANY(sqlc.arg('group_by')::TEXT[]) THEN namespace ELSE NULL END, 'all')::TEXT AS group_namespace,
    COALESCE(CASE WHEN 'workload_type' = ANY(sqlc.arg('group_by')::TEXT[]) THEN workload_type ELSE NULL END, 'all')::TEXT AS group_workload_type,
    critical,
    high,
    medium,
    low,
    unassigned,
    risk_score
FROM latest_per_workload_per_bucket
    )
SELECT
    bucket_time::timestamptz AS bucket_time,
    group_cluster,
    group_namespace,
    group_workload_type,
    SUM(COALESCE(critical, 0))::INT4 AS critical,
        SUM(COALESCE(high, 0))::INT4 AS high,
        SUM(COALESCE(medium, 0))::INT4 AS medium,
        SUM(COALESCE(low, 0))::INT4 AS low,
        SUM(COALESCE(unassigned, 0))::INT4 AS unassigned,
        SUM(COALESCE(risk_score, 0))::INT4 AS risk_score,
        COUNT(*)::INT4 AS workload_count
FROM grouped
GROUP BY
    bucket_time,
    group_cluster,
    group_namespace,
    group_workload_type
ORDER BY bucket_time;

-- name: ListCumulativeVulnerabilityTimeSeries :many
WITH filtered_workloads AS (
    SELECT
        w.image_name,
        w.cluster,
        w.namespace,
        w.workload_type,
        w.name AS workload_name
    FROM workloads w
    WHERE
        (sqlc.narg('cluster')::TEXT IS NULL OR w.cluster = sqlc.narg('cluster')::TEXT)
      AND (sqlc.narg('namespace')::TEXT IS NULL OR w.namespace = sqlc.narg('namespace')::TEXT)
      AND (sqlc.narg('workload_types')::TEXT[] IS NULL OR w.workload_type = ANY(sqlc.narg('workload_types')::TEXT[]))
      AND (sqlc.narg('workload_name')::TEXT IS NULL OR w.name = sqlc.narg('workload_name')::TEXT)
),
     joined AS (
         SELECT
             v.*,
             fw.cluster,
             fw.namespace,
             fw.workload_type,
             fw.workload_name,
             CASE
                 WHEN sqlc.narg('resolution') = 'day' THEN date_trunc('day', v.updated_at)
                 WHEN sqlc.narg('resolution') = 'week' THEN date_trunc('week', v.updated_at)
                 WHEN sqlc.narg('resolution') = 'month' THEN date_trunc('month', v.updated_at)
                 WHEN sqlc.narg('resolution') = 'hour' THEN date_trunc('hour', v.updated_at)
                 ELSE date_trunc('day', v.updated_at) -- default fallback
                 END AS bucket_time
         FROM vulnerability_summary v
                  JOIN filtered_workloads fw ON v.image_name = fw.image_name
         WHERE sqlc.narg('since')::timestamptz IS NULL
    OR v.updated_at >= sqlc.narg('since')::timestamptz
    ),
    latest_per_workload_per_bucket AS (
SELECT DISTINCT ON (workload_name, bucket_time)
    bucket_time,
    cluster,
    namespace,
    workload_type,
    critical,
    high,
    medium,
    low,
    unassigned,
    risk_score
FROM joined
ORDER BY workload_name, bucket_time, updated_at DESC
    ),
    grouped AS (
SELECT
    bucket_time,
    COALESCE(CASE WHEN 'cluster' = ANY(sqlc.arg('group_by')::TEXT[]) THEN cluster ELSE NULL END, 'all') AS group_cluster,
    COALESCE(CASE WHEN 'namespace' = ANY(sqlc.arg('group_by')::TEXT[]) THEN namespace ELSE NULL END, 'all') AS group_namespace,
    COALESCE(CASE WHEN 'workload_type' = ANY(sqlc.arg('group_by')::TEXT[]) THEN workload_type ELSE NULL END, 'all') AS group_workload_type,
    critical,
    high,
    medium,
    low,
    unassigned,
    risk_score
FROM latest_per_workload_per_bucket
    )
SELECT
    bucket_time::timestamptz AS bucket_time,
        group_cluster::TEXT AS group_cluster,
        group_namespace::TEXT AS group_namespace,
        group_workload_type::TEXT AS group_workload_type,
        SUM(critical)::INT4 AS critical,
        SUM(high)::INT4 AS high,
        SUM(medium)::INT4 AS medium,
        SUM(low)::INT4 AS low,
        SUM(unassigned)::INT4 AS unassigned,
        SUM(risk_score)::INT4 AS risk_score,
        COUNT(*)::INT4 AS workload_count
FROM grouped
GROUP BY
    bucket_time,
    group_cluster,
    group_namespace,
    group_workload_type
ORDER BY bucket_time;



-- name: GetVulnerabilitySummaryForImage :one
SELECT * FROM vulnerability_summary
WHERE image_name = @image_name
  AND image_tag = @image_tag;

-- name: BatchUpsertVulnerabilitySummary :batchexec
INSERT INTO vulnerability_summary(
    image_name,
    image_tag,
    critical,
    high,
    medium,
    low,
    unassigned,
    risk_score)
VALUES (
    @image_name,
    @image_tag,
    @critical,
    @high,
    @medium,
    @low,
    @unassigned,
    @risk_score)
ON CONFLICT ON CONSTRAINT image_name_tag
    DO UPDATE SET
        critical = @critical,
        high = @high,
        medium = @medium,
        low = @low,
        unassigned = @unassigned,
        risk_score = @risk_score,
        updated_at = NOW();

-- name: CreateVulnerabilitySummary :one
INSERT INTO vulnerability_summary(
    image_name,
    image_tag,
    critical,
    high,
    medium,
    low,
    unassigned,
    risk_score)
VALUES (
    @image_name,
    @image_tag,
    @critical,
    @high,
    @medium,
    @low,
    @unassigned,
    @risk_score)
RETURNING
    *;

-- name: ListVulnerabilitySummaries :many
WITH filtered_workloads AS (
    SELECT
        *
    FROM
        workloads w
    WHERE (sqlc.narg('cluster')::TEXT IS NULL
        OR w.cluster = sqlc.narg('cluster')::TEXT)
    AND (sqlc.narg('namespace')::TEXT IS NULL
        OR w.namespace = sqlc.narg('namespace')::TEXT)
    AND (sqlc.narg('workload_types')::TEXT[] IS NULL
        OR w.workload_type = ANY (sqlc.narg('workload_types')::TEXT[]))
    AND (sqlc.narg('workload_name')::TEXT IS NULL
        OR w.name = sqlc.narg('workload_name')::TEXT)
),
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
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND i.state = 'updated' THEN
                v.critical
            END, 0)::INT4 AS critical,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND i.state = 'updated' THEN
                v.high
            END, 0)::INT4 AS high,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND i.state = 'updated' THEN
                v.medium
            END, 0)::INT4 AS medium,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND i.state = 'updated' THEN
                v.low
            END, 0)::INT4 AS low,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND i.state = 'updated' THEN
                v.unassigned
            END, 0)::INT4 AS unassigned,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND i.state = 'updated' THEN
                v.act_now
            END, 0)::INT4 AS act_now,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND i.state = 'updated' THEN
                v.high_risk
            END, 0)::INT4 AS high_risk,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND i.state = 'updated' THEN
                v.elevated_risk
            END, 0)::INT4 AS elevated_risk,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND i.state = 'updated' THEN
                v.monitor
            END, 0)::INT4 AS monitor,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND i.state = 'updated' THEN
                v.exploitable
            END, 0)::INT4 AS exploitable,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND i.state = 'updated' THEN
                v.kev_count
            END, 0)::INT4 AS kev_count,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND i.state = 'updated' THEN
                v.ransomware_count
            END, 0)::INT4 AS ransomware_count,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND i.state = 'updated' THEN
                v.high_epss_count
            END, 0)::INT4 AS high_epss_count,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND i.state = 'updated' THEN
                v.top_risk_tier
            END) AS top_risk_tier,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND i.state = 'updated' THEN
                v.risk_score
            END, 0)::INT4 AS risk_score,
        w.created_at AS workload_created_at,
        w.updated_at AS workload_updated_at,
        v.created_at AS summary_created_at,
        v.updated_at AS summary_updated_at,
        CASE WHEN v.image_name IS NOT NULL
            AND w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
            AND i.state = 'updated' THEN
            TRUE
        ELSE
            FALSE
        END AS has_sbom,
        w.state AS workload_state,
        i.state AS image_state,
        i.sbom_processing_started_at
    FROM
        filtered_workloads w
        LEFT JOIN vulnerability_summary v ON w.image_name = v.image_name
            AND (
                CASE WHEN sqlc.narg('since')::TIMESTAMP WITH TIME ZONE IS NULL THEN
                    w.image_tag = v.image_tag
                ELSE
                    TRUE
                END)
        LEFT JOIN images i ON i.name = w.image_name
            AND i.tag = w.image_tag
    WHERE (sqlc.narg('image_name')::TEXT IS NULL
        OR v.image_name = sqlc.narg('image_name')::TEXT)
    AND (sqlc.narg('image_tag')::TEXT IS NULL
        OR v.image_tag = sqlc.narg('image_tag')::TEXT)
    AND (sqlc.narg('risk_tier')::INT IS NULL
        OR v.top_risk_tier = sqlc.narg('risk_tier')::INT)
    AND (sqlc.narg('since')::TIMESTAMP WITH TIME ZONE IS NULL
        OR v.updated_at > sqlc.narg('since')::TIMESTAMP WITH TIME ZONE))
SELECT
    *,
(
        SELECT
            COUNT(*)
        FROM
            vulnerability_data) AS total_count
FROM
    vulnerability_data
ORDER BY
    CASE WHEN sqlc.narg('order_by') = 'workload_asc' THEN
        workload_name
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'workload_desc' THEN
        workload_name
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'namespace_asc' THEN
        namespace
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'namespace_desc' THEN
        namespace
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_asc' THEN
        CLUSTER
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_desc' THEN
        CLUSTER
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'critical_asc' THEN
        COALESCE(critical, 999999)
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'critical_desc' THEN
        COALESCE(critical, -1)
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'high_asc' THEN
        COALESCE(high, 999999)
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'high_desc' THEN
        COALESCE(high, -1)
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'medium_asc' THEN
        COALESCE(medium, 999999)
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'medium_desc' THEN
        COALESCE(medium, -1)
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'low_asc' THEN
        COALESCE(low, 999999)
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'low_desc' THEN
        COALESCE(low, -1)
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'unassigned_asc' THEN
        COALESCE(unassigned, 999999)
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'unassigned_desc' THEN
        COALESCE(unassigned, -1)
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'risk_score_asc' THEN
        COALESCE(risk_score, 999999)
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'risk_score_desc' THEN
        COALESCE(risk_score, -1)
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'act_now_asc' THEN
        COALESCE(act_now, 999999)
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'act_now_desc' THEN
        COALESCE(act_now, -1)
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'high_risk_asc' THEN
        COALESCE(high_risk, 999999)
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'high_risk_desc' THEN
        COALESCE(high_risk, -1)
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'elevated_risk_asc' THEN
        COALESCE(elevated_risk, 999999)
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'elevated_risk_desc' THEN
        COALESCE(elevated_risk, -1)
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'monitor_asc' THEN
        COALESCE(monitor, 999999)
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'monitor_desc' THEN
        COALESCE(monitor, -1)
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'exploitable_asc' THEN
        COALESCE(exploitable, 999999)
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'exploitable_desc' THEN
        COALESCE(exploitable, -1)
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'kev_count_asc' THEN
        COALESCE(kev_count, 999999)
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'kev_count_desc' THEN
        COALESCE(kev_count, -1)
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'ransomware_count_asc' THEN
        COALESCE(ransomware_count, 999999)
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'ransomware_count_desc' THEN
        COALESCE(ransomware_count, -1)
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'high_epss_count_asc' THEN
        COALESCE(high_epss_count, 999999)
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'high_epss_count_desc' THEN
        COALESCE(high_epss_count, -1)
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'top_risk_tier_asc' THEN
        top_risk_tier
    END ASC NULLS LAST,
    CASE WHEN sqlc.narg('order_by') = 'top_risk_tier_desc' THEN
        top_risk_tier
    END DESC NULLS LAST,
    summary_updated_at ASC,
    id DESC
LIMIT sqlc.arg('limit')
    OFFSET sqlc.arg('offset');

-- name: GetVulnerabilitySummary :one
WITH filtered_workloads AS (
    SELECT
        w.id,
        w.image_name,
        w.image_tag,
        w.state NOT IN ('no_attestation', 'failed', 'unrecoverable') AS workload_ready
    FROM
        workloads w
    WHERE (sqlc.narg('cluster')::TEXT IS NULL
        OR w.cluster = sqlc.narg('cluster')::TEXT)
    AND (sqlc.narg('namespace')::TEXT IS NULL
        OR w.namespace = sqlc.narg('namespace')::TEXT)
    AND (sqlc.narg('workload_types')::TEXT[] IS NULL
        OR w.workload_type = ANY (sqlc.narg('workload_types')::TEXT[]))
    AND (sqlc.narg('workload_name')::TEXT IS NULL
        OR w.name = sqlc.narg('workload_name')::TEXT)
    AND (sqlc.narg('risk_tier')::INT IS NULL
        OR EXISTS (
            SELECT
                1
            FROM
                vulnerability_summary v
            WHERE
                v.image_name = w.image_name
                AND v.image_tag = w.image_tag
                AND v.top_risk_tier = sqlc.narg('risk_tier')::INT)))
SELECT
    CAST(COUNT(DISTINCT fw.id) AS INT4) AS workload_count,
    CAST(COUNT(DISTINCT CASE WHEN fw.workload_ready
                AND i.state = 'updated'
                AND v.id IS NOT NULL THEN
                fw.id
            END) AS INT4) AS workload_with_sbom,
    CAST(COALESCE(SUM(
                CASE WHEN fw.workload_ready
                    AND i.state = 'updated' THEN
                    v.critical
                END), 0) AS INT4) AS critical,
    CAST(COALESCE(SUM(
                CASE WHEN fw.workload_ready
                    AND i.state = 'updated' THEN
                    v.high
                END), 0) AS INT4) AS high,
    CAST(COALESCE(SUM(
                CASE WHEN fw.workload_ready
                    AND i.state = 'updated' THEN
                    v.medium
                END), 0) AS INT4) AS medium,
    CAST(COALESCE(SUM(
                CASE WHEN fw.workload_ready
                    AND i.state = 'updated' THEN
                    v.low
                END), 0) AS INT4) AS low,
    CAST(COALESCE(SUM(
                CASE WHEN fw.workload_ready
                    AND i.state = 'updated' THEN
                    v.unassigned
                END), 0) AS INT4) AS unassigned,
    CAST(COALESCE(SUM(
                CASE WHEN fw.workload_ready
                    AND i.state = 'updated' THEN
                    v.act_now
                END), 0) AS INT4) AS act_now,
    CAST(COALESCE(SUM(
                CASE WHEN fw.workload_ready
                    AND i.state = 'updated' THEN
                    v.high_risk
                END), 0) AS INT4) AS high_risk,
    CAST(COALESCE(SUM(
                CASE WHEN fw.workload_ready
                    AND i.state = 'updated' THEN
                    v.elevated_risk
                END), 0) AS INT4) AS elevated_risk,
    CAST(COALESCE(SUM(
                CASE WHEN fw.workload_ready
                    AND i.state = 'updated' THEN
                    v.monitor
                END), 0) AS INT4) AS monitor,
    CAST(COALESCE(SUM(
                CASE WHEN fw.workload_ready
                    AND i.state = 'updated' THEN
                    v.exploitable
                END), 0) AS INT4) AS exploitable,
    CAST(COALESCE(SUM(
                CASE WHEN fw.workload_ready
                    AND i.state = 'updated' THEN
                    v.kev_count
                END), 0) AS INT4) AS kev_count,
    CAST(COALESCE(SUM(
                CASE WHEN fw.workload_ready
                    AND i.state = 'updated' THEN
                    v.ransomware_count
                END), 0) AS INT4) AS ransomware_count,
    CAST(COALESCE(SUM(
                CASE WHEN fw.workload_ready
                    AND i.state = 'updated' THEN
                    v.high_epss_count
                END), 0) AS INT4) AS high_epss_count,
    MIN(
        CASE WHEN fw.workload_ready
            AND i.state = 'updated' THEN
            v.top_risk_tier
        END) AS top_risk_tier,
    CAST(COALESCE(SUM(
                CASE WHEN fw.workload_ready
                    AND i.state = 'updated' THEN
                    v.risk_score
                END), 0) AS INT4) AS risk_score,
    MAX(
        CASE WHEN fw.workload_ready
            AND i.state = 'updated'
            AND v.id IS NOT NULL THEN
            v.updated_at
        END)::TIMESTAMPTZ AS updated_at
FROM
    filtered_workloads fw
    LEFT JOIN vulnerability_summary v ON fw.image_name = v.image_name
        AND fw.image_tag = v.image_tag
    LEFT JOIN images i ON i.name = fw.image_name
        AND i.tag = fw.image_tag;

-- name: GetVulnerabilitySummaryTimeSeries :many
SELECT
    snapshot_date,
    SUM(workload_count)::INT4 AS workload_count,
    SUM(critical)::INT4 AS critical,
    SUM(high)::INT4 AS high,
    SUM(medium)::INT4 AS medium,
    SUM(low)::INT4 AS low,
    SUM(unassigned)::INT4 AS unassigned,
    COALESCE(SUM(act_now), 0)::INT4 AS act_now,
    COALESCE(SUM(high_risk), 0)::INT4 AS high_risk,
    COALESCE(SUM(elevated_risk), 0)::INT4 AS elevated_risk,
    COALESCE(SUM(monitor), 0)::INT4 AS monitor,
    COALESCE(SUM(exploitable), 0)::INT4 AS exploitable,
    COALESCE(SUM(kev_count), 0)::INT4 AS kev_count,
    COALESCE(SUM(ransomware_count), 0)::INT4 AS ransomware_count,
    COALESCE(SUM(high_epss_count), 0)::INT4 AS high_epss_count,
    MIN(top_risk_tier) AS top_risk_tier,
    SUM(total)::INT4 AS total,
    SUM(risk_score)::INT4 AS risk_score
FROM
    mv_vuln_summary_daily_by_workload
WHERE
    snapshot_date >= sqlc.arg('since')::TIMESTAMPTZ
    AND snapshot_date <= CURRENT_DATE
    AND (sqlc.narg('cluster')::TEXT IS NULL
        OR CLUSTER = sqlc.narg('cluster')::TEXT)
    AND (sqlc.narg('namespace')::TEXT IS NULL
        OR namespace = sqlc.narg('namespace')::TEXT)
    AND (sqlc.narg('workload_types')::TEXT[] IS NULL
        OR workload_type = ANY (sqlc.narg('workload_types')::TEXT[]))
    AND (sqlc.narg('workload_name')::TEXT IS NULL
        OR workload_name = sqlc.narg('workload_name')::TEXT)
    AND (sqlc.narg('risk_tier')::INT IS NULL
        OR top_risk_tier = sqlc.narg('risk_tier')::INT)
GROUP BY
    snapshot_date
ORDER BY
    snapshot_date;

-- name: RefreshVulnerabilitySummaryDailyView :exec
REFRESH MATERIALIZED VIEW CONCURRENTLY mv_vuln_summary_daily_by_workload;

-- name: GetVulnerabilitySummaryForImage :one
SELECT
    *
FROM
    vulnerability_summary
WHERE
    image_name = @image_name
    AND image_tag = @image_tag;

-- name: GetLatestSummaryForImageName :one
SELECT
    *
FROM
    vulnerability_summary
WHERE
    image_name = @image_name
    AND image_tag != @exclude_tag
ORDER BY
    updated_at DESC
LIMIT 1;

-- name: GetLastSnapshotDateForVulnerabilitySummary :one
SELECT
    COALESCE(MAX(snapshot_date), '2025-01-01')::DATE AS last_snapshot
FROM
    vuln_daily_by_workload;

-- name: RefreshVulnerabilitySummaryForDate :exec
WITH latest_summary_per_day AS (
    SELECT DISTINCT ON (w.id)
        @date::DATE AS snapshot_date,
        w.id AS workload_id,
        w.name AS workload_name,
        w.cluster,
        w.namespace,
        w.workload_type,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND img.state = 'updated' THEN
                vs.critical
            END, 0) AS critical,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND img.state = 'updated' THEN
                vs.high
            END, 0) AS high,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND img.state = 'updated' THEN
                vs.medium
            END, 0) AS medium,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND img.state = 'updated' THEN
                vs.low
            END, 0) AS low,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND img.state = 'updated' THEN
                vs.unassigned
            END, 0) AS unassigned,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND img.state = 'updated' THEN
                vs.act_now
            END, 0) AS act_now,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND img.state = 'updated' THEN
                vs.high_risk
            END, 0) AS high_risk,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND img.state = 'updated' THEN
                vs.elevated_risk
            END, 0) AS elevated_risk,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND img.state = 'updated' THEN
                vs.monitor
            END, 0) AS monitor,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND img.state = 'updated' THEN
                vs.exploitable
            END, 0) AS exploitable,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND img.state = 'updated' THEN
                vs.kev_count
            END, 0) AS kev_count,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND img.state = 'updated' THEN
                vs.ransomware_count
            END, 0) AS ransomware_count,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND img.state = 'updated' THEN
                vs.high_epss_count
            END, 0) AS high_epss_count,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND img.state = 'updated' THEN
                vs.top_risk_tier
            END) AS top_risk_tier,
        COALESCE(
            CASE WHEN w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
                AND img.state = 'updated' THEN
                vs.risk_score
            END, 0) AS risk_score,
(w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
            AND img.state = 'updated'
            AND vs.id IS NOT NULL) AS has_summary
    FROM
        workloads w
        LEFT JOIN images img ON img.name = w.image_name
            AND img.tag = w.image_tag
        LEFT JOIN vulnerability_summary vs ON w.image_name = vs.image_name
            AND w.image_tag = vs.image_tag
            AND vs.updated_at::DATE <= @date::DATE
        ORDER BY
            w.id,
            vs.updated_at DESC)
    INSERT INTO vuln_daily_by_workload(
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
        act_now,
        high_risk,
        elevated_risk,
        monitor,
        exploitable,
        kev_count,
        ransomware_count,
        high_epss_count,
        top_risk_tier,
        total,
        risk_score,
        has_summary)
    SELECT
        snapshot_date,
        workload_id,
        workload_name,
        CLUSTER,
        namespace,
        workload_type,
        COALESCE(critical, 0)::INT4,
        COALESCE(high, 0)::INT4,
        COALESCE(medium, 0)::INT4,
        COALESCE(low, 0)::INT4,
        COALESCE(unassigned, 0)::INT4,
        COALESCE(act_now, 0)::INT4,
        COALESCE(high_risk, 0)::INT4,
        COALESCE(elevated_risk, 0)::INT4,
        COALESCE(monitor, 0)::INT4,
        COALESCE(exploitable, 0)::INT4,
        COALESCE(kev_count, 0)::INT4,
        COALESCE(ransomware_count, 0)::INT4,
        COALESCE(high_epss_count, 0)::INT4,
        top_risk_tier,
(COALESCE(critical, 0) + COALESCE(high, 0) + COALESCE(medium, 0) + COALESCE(low, 0) + COALESCE(unassigned, 0))::INT4,
        COALESCE(risk_score, 0)::INT4,
        has_summary
    FROM
        latest_summary_per_day
    ON CONFLICT (snapshot_date,
        workload_id)
        DO UPDATE SET
            critical = EXCLUDED.critical,
            high = EXCLUDED.high,
            medium = EXCLUDED.medium,
            low = EXCLUDED.low,
            unassigned = EXCLUDED.unassigned,
            act_now = EXCLUDED.act_now,
            high_risk = EXCLUDED.high_risk,
            elevated_risk = EXCLUDED.elevated_risk,
            monitor = EXCLUDED.monitor,
            exploitable = EXCLUDED.exploitable,
            kev_count = EXCLUDED.kev_count,
            ransomware_count = EXCLUDED.ransomware_count,
            high_epss_count = EXCLUDED.high_epss_count,
            top_risk_tier = EXCLUDED.top_risk_tier,
            total = EXCLUDED.total,
            risk_score = EXCLUDED.risk_score,
            has_summary = EXCLUDED.has_summary;

-- name: ListUpdatedWorkloadsWithSummaries :many
SELECT
    w.cluster,
    w.namespace,
    w.name,
    w.image_name,
    w.image_tag,
    w.state AS workload_state,
    i.state AS image_state,
    s.critical,
    s.high,
    s.medium,
    s.low,
    s.unassigned,
    s.act_now,
    s.high_risk,
    s.elevated_risk,
    s.monitor,
    s.exploitable,
    s.kev_count,
    s.ransomware_count,
    s.high_epss_count,
    s.top_risk_tier,
    s.risk_score
FROM
    workloads w
    JOIN images i ON i.name = w.image_name
        AND i.tag = w.image_tag
    JOIN vulnerability_summary s ON s.image_name = w.image_name
        AND s.image_tag = w.image_tag
WHERE
    w.state = 'updated'
    AND i.state = 'updated'
ORDER BY
    w.cluster,
    w.namespace,
    w.name;

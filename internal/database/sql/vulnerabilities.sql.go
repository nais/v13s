// Code generated by sqlc. DO NOT EDIT.
// source: vulnerabilities.sql

package sql

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	typeext "github.com/nais/v13s/internal/database/typeext"
)

const countVulnerabilities = `-- name: CountVulnerabilities :one
SELECT COUNT(*) AS total
FROM vulnerabilities v
         JOIN cve c ON v.cve_id = c.cve_id
         JOIN workloads w ON v.image_name = w.image_name AND v.image_tag = w.image_tag
         LEFT JOIN suppressed_vulnerabilities sv
                   ON v.image_name = sv.image_name
                       AND v.package = sv.package
                       AND v.cve_id = sv.cve_id
WHERE (CASE WHEN $1::TEXT is not null THEN w.cluster = $1::TEXT ELSE TRUE END)
  AND (CASE WHEN $2::TEXT is not null THEN w.namespace = $2::TEXT ELSE TRUE END)
  AND (CASE
           WHEN $3::TEXT is not null THEN w.workload_type = $3::TEXT
           ELSE TRUE END)
  AND (CASE
           WHEN $4::TEXT is not null THEN w.name = $4::TEXT
           ELSE TRUE END)
  AND ($5::BOOLEAN IS TRUE OR COALESCE(sv.suppressed, FALSE) = FALSE)
`

type CountVulnerabilitiesParams struct {
	Cluster           *string
	Namespace         *string
	WorkloadType      *string
	WorkloadName      *string
	IncludeSuppressed *bool
}

func (q *Queries) CountVulnerabilities(ctx context.Context, arg CountVulnerabilitiesParams) (int64, error) {
	row := q.db.QueryRow(ctx, countVulnerabilities,
		arg.Cluster,
		arg.Namespace,
		arg.WorkloadType,
		arg.WorkloadName,
		arg.IncludeSuppressed,
	)
	var total int64
	err := row.Scan(&total)
	return total, err
}

const countVulnerabilitiesForImage = `-- name: CountVulnerabilitiesForImage :one
SELECT COUNT(*) AS total
FROM vulnerabilities v
         JOIN cve c ON v.cve_id = c.cve_id
         JOIN workloads w ON v.image_name = w.image_name AND v.image_tag = w.image_tag
         LEFT JOIN suppressed_vulnerabilities sv
                   ON v.image_name = sv.image_name
                       AND v.package = sv.package
                       AND v.cve_id = sv.cve_id
WHERE v.image_name = $1
    AND v.image_tag = $2
    AND ($3::BOOLEAN IS TRUE OR COALESCE(sv.suppressed, FALSE) = FALSE)
`

type CountVulnerabilitiesForImageParams struct {
	ImageName         string
	ImageTag          string
	IncludeSuppressed *bool
}

func (q *Queries) CountVulnerabilitiesForImage(ctx context.Context, arg CountVulnerabilitiesForImageParams) (int64, error) {
	row := q.db.QueryRow(ctx, countVulnerabilitiesForImage, arg.ImageName, arg.ImageTag, arg.IncludeSuppressed)
	var total int64
	err := row.Scan(&total)
	return total, err
}

const generateVulnerabilitySummaryForImage = `-- name: GenerateVulnerabilitySummaryForImage :one
SELECT COUNT(*) AS total,
       SUM(CASE WHEN c.severity = 5 THEN 1 ELSE 0 END) AS critical,
       SUM(CASE WHEN c.severity = 4 THEN 1 ELSE 0 END) AS high,
       SUM(CASE WHEN c.severity = 3 THEN 1 ELSE 0 END) AS medium,
       SUM(CASE WHEN c.severity = 2 THEN 1 ELSE 0 END) AS low,
       SUM(CASE WHEN c.severity = 1 THEN 1 ELSE 0 END) AS unassigned,
       -- 10*critical + 5*high + 3*medium + 1*low + 5*unassigned
         10 * SUM(CASE WHEN c.severity = 5 THEN 1 ELSE 0 END) +
            5 * SUM(CASE WHEN c.severity = 4 THEN 1 ELSE 0 END) +
            3 * SUM(CASE WHEN c.severity = 3 THEN 1 ELSE 0 END) +
            1 * SUM(CASE WHEN c.severity = 2 THEN 1 ELSE 0 END) +
            5 * SUM(CASE WHEN c.severity = 1 THEN 1 ELSE 0 END) AS risk_score

FROM vulnerabilities v
         JOIN cve c ON v.cve_id = c.cve_id
WHERE v.image_name = $1
    AND v.image_tag = $2
`

type GenerateVulnerabilitySummaryForImageParams struct {
	ImageName string
	ImageTag  string
}

type GenerateVulnerabilitySummaryForImageRow struct {
	Total      int64
	Critical   int64
	High       int64
	Medium     int64
	Low        int64
	Unassigned int64
	RiskScore  int32
}

func (q *Queries) GenerateVulnerabilitySummaryForImage(ctx context.Context, arg GenerateVulnerabilitySummaryForImageParams) (*GenerateVulnerabilitySummaryForImageRow, error) {
	row := q.db.QueryRow(ctx, generateVulnerabilitySummaryForImage, arg.ImageName, arg.ImageTag)
	var i GenerateVulnerabilitySummaryForImageRow
	err := row.Scan(
		&i.Total,
		&i.Critical,
		&i.High,
		&i.Medium,
		&i.Low,
		&i.Unassigned,
		&i.RiskScore,
	)
	return &i, err
}

const getCve = `-- name: GetCve :one
SELECT cve_id, cve_title, cve_desc, cve_link, severity, refs, created_at, updated_at
FROM cve
WHERE cve_id = $1
`

func (q *Queries) GetCve(ctx context.Context, cveID string) (*Cve, error) {
	row := q.db.QueryRow(ctx, getCve, cveID)
	var i Cve
	err := row.Scan(
		&i.CveID,
		&i.CveTitle,
		&i.CveDesc,
		&i.CveLink,
		&i.Severity,
		&i.Refs,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return &i, err
}

const getSuppressedVulnerability = `-- name: GetSuppressedVulnerability :one
SELECT id, image_name, package, cve_id, suppressed, reason, reason_text, created_at, updated_at
FROM suppressed_vulnerabilities
WHERE image_name = $1
  AND package = $2
  AND cve_id = $3
`

type GetSuppressedVulnerabilityParams struct {
	ImageName string
	Package   string
	CveID     string
}

func (q *Queries) GetSuppressedVulnerability(ctx context.Context, arg GetSuppressedVulnerabilityParams) (*SuppressedVulnerability, error) {
	row := q.db.QueryRow(ctx, getSuppressedVulnerability, arg.ImageName, arg.Package, arg.CveID)
	var i SuppressedVulnerability
	err := row.Scan(
		&i.ID,
		&i.ImageName,
		&i.Package,
		&i.CveID,
		&i.Suppressed,
		&i.Reason,
		&i.ReasonText,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return &i, err
}

const getVulnerability = `-- name: GetVulnerability :one
SELECT id, image_name, image_tag, package, cve_id, source, latest_version, created_at, updated_at
FROM vulnerabilities
WHERE image_name = $1
  AND image_tag = $2
  AND package = $3
  AND cve_id = $4
`

type GetVulnerabilityParams struct {
	ImageName string
	ImageTag  string
	Package   string
	CveID     string
}

func (q *Queries) GetVulnerability(ctx context.Context, arg GetVulnerabilityParams) (*Vulnerability, error) {
	row := q.db.QueryRow(ctx, getVulnerability,
		arg.ImageName,
		arg.ImageTag,
		arg.Package,
		arg.CveID,
	)
	var i Vulnerability
	err := row.Scan(
		&i.ID,
		&i.ImageName,
		&i.ImageTag,
		&i.Package,
		&i.CveID,
		&i.Source,
		&i.LatestVersion,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return &i, err
}

const listSuppressedVulnerabilitiesForImage = `-- name: ListSuppressedVulnerabilitiesForImage :many
SELECT id, image_name, package, cve_id, suppressed, reason, reason_text, created_at, updated_at
FROM suppressed_vulnerabilities
WHERE image_name = $1
ORDER BY updated_at DESC
LIMIT $3 OFFSET $2
`

type ListSuppressedVulnerabilitiesForImageParams struct {
	ImageName string
	Offset    int32
	Limit     int32
}

func (q *Queries) ListSuppressedVulnerabilitiesForImage(ctx context.Context, arg ListSuppressedVulnerabilitiesForImageParams) ([]*SuppressedVulnerability, error) {
	rows, err := q.db.Query(ctx, listSuppressedVulnerabilitiesForImage, arg.ImageName, arg.Offset, arg.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []*SuppressedVulnerability{}
	for rows.Next() {
		var i SuppressedVulnerability
		if err := rows.Scan(
			&i.ID,
			&i.ImageName,
			&i.Package,
			&i.CveID,
			&i.Suppressed,
			&i.Reason,
			&i.ReasonText,
			&i.CreatedAt,
			&i.UpdatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, &i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const listVulnerabilities = `-- name: ListVulnerabilities :many
SELECT w.name                         AS workload_name,
       w.workload_type,
       w.namespace,
       w.cluster,
       v.image_name,
       v.image_tag,
       v.package,
       v.cve_id,
       v.created_at,
       v.updated_at,
       c.cve_title,
       c.cve_desc,
       c.cve_link,
       c.severity,
       COALESCE(sv.suppressed, FALSE) AS suppressed,
       sv.reason,
       sv.reason_text
FROM vulnerabilities v
         JOIN cve c ON v.cve_id = c.cve_id
         JOIN workloads w ON v.image_name = w.image_name AND v.image_tag = w.image_tag
         LEFT JOIN suppressed_vulnerabilities sv
                   ON v.image_name = sv.image_name
                       AND v.package = sv.package
                       AND v.cve_id = sv.cve_id
WHERE (CASE WHEN $1::TEXT is not null THEN w.cluster = $1::TEXT ELSE TRUE END)
  AND (CASE WHEN $2::TEXT is not null THEN w.namespace = $2::TEXT ELSE TRUE END)
  AND (CASE
           WHEN $3::TEXT is not null THEN w.workload_type = $3::TEXT
           ELSE TRUE END)
  AND (CASE
           WHEN $4::TEXT is not null THEN w.name = $4::TEXT
           ELSE TRUE END)
  AND (CASE
           WHEN $5::TEXT is not null THEN v.image_name = $5::TEXT
           ELSE TRUE END)
  AND (CASE WHEN $6::TEXT is not null THEN v.image_tag = $6::TEXT ELSE TRUE END)
  AND ($7::BOOLEAN IS TRUE OR COALESCE(sv.suppressed, FALSE) = FALSE)
ORDER BY (w.cluster, w.namespace, w.name, v.id) ASC
LIMIT $9 OFFSET $8
`

type ListVulnerabilitiesParams struct {
	Cluster           *string
	Namespace         *string
	WorkloadType      *string
	WorkloadName      *string
	ImageName         *string
	ImageTag          *string
	IncludeSuppressed *bool
	Offset            int32
	Limit             int32
}

type ListVulnerabilitiesRow struct {
	WorkloadName string
	WorkloadType string
	Namespace    string
	Cluster      string
	ImageName    string
	ImageTag     string
	Package      string
	CveID        string
	CreatedAt    pgtype.Timestamptz
	UpdatedAt    pgtype.Timestamptz
	CveTitle     string
	CveDesc      string
	CveLink      string
	Severity     int32
	Suppressed   bool
	Reason       NullVulnerabilitySuppressReason
	ReasonText   *string
}

func (q *Queries) ListVulnerabilities(ctx context.Context, arg ListVulnerabilitiesParams) ([]*ListVulnerabilitiesRow, error) {
	rows, err := q.db.Query(ctx, listVulnerabilities,
		arg.Cluster,
		arg.Namespace,
		arg.WorkloadType,
		arg.WorkloadName,
		arg.ImageName,
		arg.ImageTag,
		arg.IncludeSuppressed,
		arg.Offset,
		arg.Limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []*ListVulnerabilitiesRow{}
	for rows.Next() {
		var i ListVulnerabilitiesRow
		if err := rows.Scan(
			&i.WorkloadName,
			&i.WorkloadType,
			&i.Namespace,
			&i.Cluster,
			&i.ImageName,
			&i.ImageTag,
			&i.Package,
			&i.CveID,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.CveTitle,
			&i.CveDesc,
			&i.CveLink,
			&i.Severity,
			&i.Suppressed,
			&i.Reason,
			&i.ReasonText,
		); err != nil {
			return nil, err
		}
		items = append(items, &i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const listVulnerabilitiesForImage = `-- name: ListVulnerabilitiesForImage :many
SELECT v.image_name,
       v.image_tag,
       v.package,
       v.cve_id,
       v.latest_version,
       v.created_at,
       v.updated_at,
       c.cve_title,
       c.cve_desc,
       c.cve_link,
       c.severity,
       c.refs,
       COALESCE(sv.suppressed, FALSE) AS suppressed,
       sv.reason,
       sv.reason_text
FROM vulnerabilities v
        JOIN cve c ON v.cve_id = c.cve_id
        LEFT JOIN suppressed_vulnerabilities sv
                ON v.image_name = sv.image_name
                    AND v.package = sv.package
                    AND v.cve_id = sv.cve_id
WHERE v.image_name = $1
    AND v.image_tag = $2
    AND ($3::BOOLEAN IS TRUE OR COALESCE(sv.suppressed, FALSE) = FALSE)
ORDER BY (c.severity, v.id) ASC
    LIMIT $5 OFFSET $4
`

type ListVulnerabilitiesForImageParams struct {
	ImageName         string
	ImageTag          string
	IncludeSuppressed *bool
	Offset            int32
	Limit             int32
}

type ListVulnerabilitiesForImageRow struct {
	ImageName     string
	ImageTag      string
	Package       string
	CveID         string
	LatestVersion string
	CreatedAt     pgtype.Timestamptz
	UpdatedAt     pgtype.Timestamptz
	CveTitle      string
	CveDesc       string
	CveLink       string
	Severity      int32
	Refs          typeext.MapStringString
	Suppressed    bool
	Reason        NullVulnerabilitySuppressReason
	ReasonText    *string
}

func (q *Queries) ListVulnerabilitiesForImage(ctx context.Context, arg ListVulnerabilitiesForImageParams) ([]*ListVulnerabilitiesForImageRow, error) {
	rows, err := q.db.Query(ctx, listVulnerabilitiesForImage,
		arg.ImageName,
		arg.ImageTag,
		arg.IncludeSuppressed,
		arg.Offset,
		arg.Limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []*ListVulnerabilitiesForImageRow{}
	for rows.Next() {
		var i ListVulnerabilitiesForImageRow
		if err := rows.Scan(
			&i.ImageName,
			&i.ImageTag,
			&i.Package,
			&i.CveID,
			&i.LatestVersion,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.CveTitle,
			&i.CveDesc,
			&i.CveLink,
			&i.Severity,
			&i.Refs,
			&i.Suppressed,
			&i.Reason,
			&i.ReasonText,
		); err != nil {
			return nil, err
		}
		items = append(items, &i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const suppressVulnerability = `-- name: SuppressVulnerability :exec
INSERT INTO suppressed_vulnerabilities(image_name,
                                       package,
                                       cve_id,
                                       suppressed,
                                       reason,
                                       reason_text)
VALUES ($1,
        $2,
        $3,
        $4,
        $5,
        $6)
ON CONFLICT
    ON CONSTRAINT image_name_package_cve_id DO UPDATE
    SET suppressed  = $4,
        reason      = $5,
        reason_text = $6
`

type SuppressVulnerabilityParams struct {
	ImageName  string
	Package    string
	CveID      string
	Suppressed bool
	Reason     VulnerabilitySuppressReason
	ReasonText string
}

func (q *Queries) SuppressVulnerability(ctx context.Context, arg SuppressVulnerabilityParams) error {
	_, err := q.db.Exec(ctx, suppressVulnerability,
		arg.ImageName,
		arg.Package,
		arg.CveID,
		arg.Suppressed,
		arg.Reason,
		arg.ReasonText,
	)
	return err
}

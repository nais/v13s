// Code generated by sqlc. DO NOT EDIT.
// source: vulnerabilities.sql

package sql

import (
	"context"
)

const getCwe = `-- name: GetCwe :one
SELECT cwe_id, cwe_title, cwe_desc, cwe_link, severity, created_at, updated_at FROM cwe WHERE cwe_id = $1
`

func (q *Queries) GetCwe(ctx context.Context, cweID string) (*Cwe, error) {
	row := q.db.QueryRow(ctx, getCwe, cweID)
	var i Cwe
	err := row.Scan(
		&i.CweID,
		&i.CweTitle,
		&i.CweDesc,
		&i.CweLink,
		&i.Severity,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return &i, err
}

const getVulnerability = `-- name: GetVulnerability :one
SELECT id, image_name, image_tag, package, cwe_id, created_at, updated_at FROM vulnerabilities WHERE image_name = $1 AND image_tag = $2 AND package = $3 AND cwe_id = $4
`

type GetVulnerabilityParams struct {
	ImageName string
	ImageTag  string
	Package   string
	CweID     string
}

func (q *Queries) GetVulnerability(ctx context.Context, arg GetVulnerabilityParams) (*Vulnerability, error) {
	row := q.db.QueryRow(ctx, getVulnerability,
		arg.ImageName,
		arg.ImageTag,
		arg.Package,
		arg.CweID,
	)
	var i Vulnerability
	err := row.Scan(
		&i.ID,
		&i.ImageName,
		&i.ImageTag,
		&i.Package,
		&i.CweID,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return &i, err
}

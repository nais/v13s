// Code generated by sqlc. DO NOT EDIT.
// source: batch.go

package sql

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	typeext "github.com/nais/v13s/internal/database/typeext"
)

var (
	ErrBatchAlreadyClosed = errors.New("batch already closed")
)

const batchUpdateImageState = `-- name: BatchUpdateImageState :batchexec
UPDATE images
SET
    state = $1,
    updated_at = NOW()
WHERE name = $2 AND tag = $3
`

type BatchUpdateImageStateBatchResults struct {
	br     pgx.BatchResults
	tot    int
	closed bool
}

type BatchUpdateImageStateParams struct {
	State ImageState
	Name  string
	Tag   string
}

func (q *Queries) BatchUpdateImageState(ctx context.Context, arg []BatchUpdateImageStateParams) *BatchUpdateImageStateBatchResults {
	batch := &pgx.Batch{}
	for _, a := range arg {
		vals := []interface{}{
			a.State,
			a.Name,
			a.Tag,
		}
		batch.Queue(batchUpdateImageState, vals...)
	}
	br := q.db.SendBatch(ctx, batch)
	return &BatchUpdateImageStateBatchResults{br, len(arg), false}
}

func (b *BatchUpdateImageStateBatchResults) Exec(f func(int, error)) {
	defer b.br.Close()
	for t := 0; t < b.tot; t++ {
		if b.closed {
			if f != nil {
				f(t, ErrBatchAlreadyClosed)
			}
			continue
		}
		_, err := b.br.Exec()
		if f != nil {
			f(t, err)
		}
	}
}

func (b *BatchUpdateImageStateBatchResults) Close() error {
	b.closed = true
	return b.br.Close()
}

const batchUpsertCve = `-- name: BatchUpsertCve :batchexec
INSERT INTO cve(cve_id,
                cve_title,
                cve_desc,
                cve_link,
                severity,
                refs)
VALUES ($1,
        $2,
        $3,
        $4,
        $5,
        $6)
    ON CONFLICT (cve_id)
    DO UPDATE
               SET cve_title = EXCLUDED.cve_title,
               cve_desc  = EXCLUDED.cve_desc,
               cve_link  = EXCLUDED.cve_link,
               severity  = EXCLUDED.severity,
               refs      = EXCLUDED.refs
       WHERE NOT (
           cve.cve_title = EXCLUDED.cve_title
         AND cve.cve_desc = EXCLUDED.cve_desc
         AND cve.cve_link = EXCLUDED.cve_link
         AND cve.severity = EXCLUDED.severity
         AND cve.refs = EXCLUDED.refs
           )
`

type BatchUpsertCveBatchResults struct {
	br     pgx.BatchResults
	tot    int
	closed bool
}

type BatchUpsertCveParams struct {
	CveID    string
	CveTitle string
	CveDesc  string
	CveLink  string
	Severity int32
	Refs     typeext.MapStringString
}

func (q *Queries) BatchUpsertCve(ctx context.Context, arg []BatchUpsertCveParams) *BatchUpsertCveBatchResults {
	batch := &pgx.Batch{}
	for _, a := range arg {
		vals := []interface{}{
			a.CveID,
			a.CveTitle,
			a.CveDesc,
			a.CveLink,
			a.Severity,
			a.Refs,
		}
		batch.Queue(batchUpsertCve, vals...)
	}
	br := q.db.SendBatch(ctx, batch)
	return &BatchUpsertCveBatchResults{br, len(arg), false}
}

func (b *BatchUpsertCveBatchResults) Exec(f func(int, error)) {
	defer b.br.Close()
	for t := 0; t < b.tot; t++ {
		if b.closed {
			if f != nil {
				f(t, ErrBatchAlreadyClosed)
			}
			continue
		}
		_, err := b.br.Exec()
		if f != nil {
			f(t, err)
		}
	}
}

func (b *BatchUpsertCveBatchResults) Close() error {
	b.closed = true
	return b.br.Close()
}

const batchUpsertVulnerabilities = `-- name: BatchUpsertVulnerabilities :batchexec
INSERT INTO vulnerabilities(image_name,
                            image_tag,
                            package,
                            cve_id,
                            source,
                            latest_version)
VALUES ($1,
        $2,
        $3,
        $4,
        $5,
        $6)
ON CONFLICT (image_name, image_tag, package, cve_id)
DO UPDATE
    SET latest_version = EXCLUDED.latest_version
    WHERE vulnerabilities.latest_version <> EXCLUDED.latest_version
`

type BatchUpsertVulnerabilitiesBatchResults struct {
	br     pgx.BatchResults
	tot    int
	closed bool
}

type BatchUpsertVulnerabilitiesParams struct {
	ImageName     string
	ImageTag      string
	Package       string
	CveID         string
	Source        string
	LatestVersion string
}

func (q *Queries) BatchUpsertVulnerabilities(ctx context.Context, arg []BatchUpsertVulnerabilitiesParams) *BatchUpsertVulnerabilitiesBatchResults {
	batch := &pgx.Batch{}
	for _, a := range arg {
		vals := []interface{}{
			a.ImageName,
			a.ImageTag,
			a.Package,
			a.CveID,
			a.Source,
			a.LatestVersion,
		}
		batch.Queue(batchUpsertVulnerabilities, vals...)
	}
	br := q.db.SendBatch(ctx, batch)
	return &BatchUpsertVulnerabilitiesBatchResults{br, len(arg), false}
}

func (b *BatchUpsertVulnerabilitiesBatchResults) Exec(f func(int, error)) {
	defer b.br.Close()
	for t := 0; t < b.tot; t++ {
		if b.closed {
			if f != nil {
				f(t, ErrBatchAlreadyClosed)
			}
			continue
		}
		_, err := b.br.Exec()
		if f != nil {
			f(t, err)
		}
	}
}

func (b *BatchUpsertVulnerabilitiesBatchResults) Close() error {
	b.closed = true
	return b.br.Close()
}

const batchUpsertVulnerabilitySummary = `-- name: BatchUpsertVulnerabilitySummary :batchexec
INSERT INTO vulnerability_summary(image_name,
                                  image_tag,
                                  critical,
                                  high,
                                  medium,
                                  low,
                                  unassigned,
                                  risk_score)
VALUES ($1,
        $2,
        $3,
        $4,
        $5,
        $6,
        $7,
        $8) ON CONFLICT
ON CONSTRAINT image_name_tag DO
UPDATE
    SET critical = $3,
    high = $4,
    medium = $5,
    low = $6,
    unassigned = $7,
    risk_score = $8,
    updated_at = NOW()
`

type BatchUpsertVulnerabilitySummaryBatchResults struct {
	br     pgx.BatchResults
	tot    int
	closed bool
}

type BatchUpsertVulnerabilitySummaryParams struct {
	ImageName  string
	ImageTag   string
	Critical   int32
	High       int32
	Medium     int32
	Low        int32
	Unassigned int32
	RiskScore  int32
}

func (q *Queries) BatchUpsertVulnerabilitySummary(ctx context.Context, arg []BatchUpsertVulnerabilitySummaryParams) *BatchUpsertVulnerabilitySummaryBatchResults {
	batch := &pgx.Batch{}
	for _, a := range arg {
		vals := []interface{}{
			a.ImageName,
			a.ImageTag,
			a.Critical,
			a.High,
			a.Medium,
			a.Low,
			a.Unassigned,
			a.RiskScore,
		}
		batch.Queue(batchUpsertVulnerabilitySummary, vals...)
	}
	br := q.db.SendBatch(ctx, batch)
	return &BatchUpsertVulnerabilitySummaryBatchResults{br, len(arg), false}
}

func (b *BatchUpsertVulnerabilitySummaryBatchResults) Exec(f func(int, error)) {
	defer b.br.Close()
	for t := 0; t < b.tot; t++ {
		if b.closed {
			if f != nil {
				f(t, ErrBatchAlreadyClosed)
			}
			continue
		}
		_, err := b.br.Exec()
		if f != nil {
			f(t, err)
		}
	}
}

func (b *BatchUpsertVulnerabilitySummaryBatchResults) Close() error {
	b.closed = true
	return b.br.Close()
}

package updater

import (
	"context"
	"fmt"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/dependencytrack"
	"github.com/nais/v13s/internal/dependencytrack/client"
	log "github.com/sirupsen/logrus"
	"time"
)

type Updater struct {
	db     sql.Querier
	source dependencytrack.Client
}

func NewUpdater(db sql.Querier, source dependencytrack.Client) *Updater {
	return &Updater{source: source}
}

// TODO: go routines and interval
func (u *Updater) UpdateForImage(ctx context.Context, imageName, imageTag string) error {
	p, err := u.source.GetProject(ctx, imageName, imageTag)
	if err != nil {
		return err
	}

	if p == nil || p.Metrics == nil {
		return nil
	}

	summary := sql.UpsertVulnerabilitySummaryParams{
		ImageName: imageName,
		ImageTag:  imageTag,
		Critical:  p.Metrics.Critical,
		High:      p.Metrics.High,
		Medium:    p.Metrics.Medium,
		Low:       p.Metrics.Low,
	}

	if p.Metrics.Unassigned != nil {
		summary.Unassigned = *p.Metrics.Unassigned
	}

	if p.Metrics.InheritedRiskScore != nil {
		summary.RiskScore = int32(*p.Metrics.InheritedRiskScore)
	}

	err = u.db.UpsertVulnerabilitySummary(ctx, summary)
	if err != nil {
		return err
	}

	_, err = u.updateVulnerabilities(ctx, *p)
	if err != nil {
		return err
	}

	return nil
}

// TODO: use transactions to ensure consistency
func (u *Updater) updateVulnerabilities(ctx context.Context, project client.Project) (any, error) {
	findings, err := u.source.GetFindings(ctx, project.Uuid, true)
	if err != nil {
		return nil, err
	}
	cweParams := make([]sql.BatchUpsertCweParams, 0)
	vulnParams := make([]sql.BatchUpsertVulnerabilitiesParams, 0)
	for _, f := range findings {
		v, cwe, err := u.parseFinding(*project.Name, *project.Version, f)
		if err != nil {
			return nil, err
		}
		cweParams = append(cweParams, sql.BatchUpsertCweParams{
			CweID:    cwe.CweID,
			CweTitle: cwe.CweTitle,
			CweDesc:  cwe.CweDesc,
			CweLink:  cwe.CweLink,
			Severity: cwe.Severity,
		})
		vulnParams = append(vulnParams, sql.BatchUpsertVulnerabilitiesParams{
			ImageName: v.ImageName,
			ImageTag:  v.ImageTag,
			Package:   v.Package,
			CweID:     v.CweID,
		})
	}

	// TODO: how to handle errors here?
	_, errors := u.upsertBatchCwe(ctx, cweParams)
	if errors > 0 {
		return nil, fmt.Errorf("error upserting CWEs, num errors: %d", errors)
	}

	_, errors = u.upsertBatchVulnerabilities(ctx, vulnParams)
	if errors > 0 {
		return nil, fmt.Errorf("error upserting CWEs, num errors: %d", errors)
	}

	return nil, nil
}

func (u *Updater) upsertBatchVulnerabilities(ctx context.Context, batch []sql.BatchUpsertVulnerabilitiesParams) (upserted, errors int) {
	if len(batch) == 0 {
		return
	}

	start := time.Now()
	var batchErr error

	u.db.BatchUpsertVulnerabilities(ctx, batch).Exec(func(i int, err error) {
		if err != nil {
			batchErr = err
			errors++
		}
	})

	upserted += len(batch) - errors
	log.WithError(batchErr).WithFields(log.Fields{
		"duration":   time.Since(start),
		"num_rows":   upserted,
		"num_errors": errors,
	}).Infof("upserted batch")
	return
}

func (u *Updater) upsertBatchCwe(ctx context.Context, batch []sql.BatchUpsertCweParams) (upserted, errors int) {
	if len(batch) == 0 {
		return
	}

	start := time.Now()
	var batchErr error

	u.db.BatchUpsertCwe(ctx, batch).Exec(func(i int, err error) {
		if err != nil {
			batchErr = err
			errors++
		}
	})

	upserted += len(batch) - errors
	log.WithError(batchErr).WithFields(log.Fields{
		"duration":   time.Since(start),
		"num_rows":   upserted,
		"num_errors": errors,
	}).Infof("upserted batch")
	return
}

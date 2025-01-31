package updater

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/dependencytrack"
	"github.com/nais/v13s/internal/dependencytrack/client"
	log "github.com/sirupsen/logrus"
	"time"
)

const (
	DefaultResyncImagesOlderThanMinutes = 60 * 12 // 12 hours
)

type Updater struct {
	db                           sql.Querier
	source                       dependencytrack.Client
	resyncImagesOlderThanMinutes time.Duration
	updateInterval               time.Duration
}

func NewUpdater(db sql.Querier, source dependencytrack.Client, updateInterval time.Duration) *Updater {
	return &Updater{
		db:                           db,
		source:                       source,
		resyncImagesOlderThanMinutes: DefaultResyncImagesOlderThanMinutes,
		updateInterval:               updateInterval,
	}
}

func (u *Updater) Run(ctx context.Context) error {
	ticker := time.NewTicker(u.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Updater stopped")
			return ctx.Err()
		case <-ticker.C:
			log.Info("Starting scheduled resync")

			if err := u.MarkForResync(ctx); err != nil {
				log.WithError(err).Error("Failed to mark images for resync")
				continue
			}

			if err := u.ResyncImages(ctx); err != nil {
				log.WithError(err).Error("Failed to resync images")
			}
		}
	}
}

// TODO: use transactions to ensure consistency
func (u *Updater) QueueImage(ctx context.Context, imageName, imageTag string) error {
	/*err := u.db.UpdateImageState(ctx, sql.UpdateImageStateParams{
		State: sql.ImageStateQueued,
		Name:  imageName,
		Tag:   imageTag,
	})
	if err != nil {
		return err
	}*/

	errCh := make(chan error, 1)

	go func() {
		defer close(errCh) // Close channel after execution
		err := u.updateForImage(ctx, imageName, imageTag)
		if err != nil {
			log.WithError(err).Errorf("Error updating image")

			if dbErr := u.db.UpdateImageState(ctx, sql.UpdateImageStateParams{
				State: sql.ImageStateFailed,
				Name:  imageName,
				Tag:   imageTag,
			}); dbErr != nil {
				log.WithError(dbErr).Errorf("Error updating image state")
			}

			errCh <- err
		}
	}()

	// Handle error if needed (non-blocking)
	select {
	case err := <-errCh:
		return fmt.Errorf("error processing image %s:%s: %w", imageName, imageTag, err)
	default:
		return nil
	}
}

func (u *Updater) ResyncImages(ctx context.Context) error {
	images, err := u.db.GetImagesScheduledForSync(ctx)
	if err != nil {
		return err
	}

	for _, image := range images {
		err = u.QueueImage(ctx, image.Name, image.Tag)
		if err != nil {
			log.WithError(err).Errorf("error queuing image")
		}
	}

	return nil
}

func (u *Updater) MarkForResync(ctx context.Context) error {
	err := u.db.MarkImagesForResync(ctx,
		pgtype.Timestamptz{
			Time:  time.Now().Add(-u.resyncImagesOlderThanMinutes * time.Minute),
			Valid: true,
		})
	if err != nil {
		return err
	}
	return nil
}

// TODO: go routines and interval
// TODO: use transactions to ensure consistency
func (u *Updater) updateForImage(ctx context.Context, imageName, imageTag string) error {
	p, err := u.source.GetProject(ctx, imageName, imageTag)
	if err != nil {
		return fmt.Errorf("error getting project: %w", err)
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

	err = u.db.UpdateImageState(ctx, sql.UpdateImageStateParams{
		State: sql.ImageStateUpdated,
		Name:  imageName,
		Tag:   imageTag,
	})

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
	CveParams := make([]sql.BatchUpsertCveParams, 0)
	vulnParams := make([]sql.BatchUpsertVulnerabilitiesParams, 0)
	for _, f := range findings {
		v, Cve, err := u.parseFinding(*project.Name, *project.Version, f)
		if err != nil {
			return nil, err
		}
		CveParams = append(CveParams, sql.BatchUpsertCveParams{
			CveID:    Cve.CveID,
			CveTitle: Cve.CveTitle,
			CveDesc:  Cve.CveDesc,
			CveLink:  Cve.CveLink,
			Severity: Cve.Severity,
		})
		vulnParams = append(vulnParams, sql.BatchUpsertVulnerabilitiesParams{
			ImageName: v.ImageName,
			ImageTag:  v.ImageTag,
			Package:   v.Package,
			CveID:     v.CveID,
		})
	}

	// TODO: how to handle errors here?
	_, errors := u.upsertBatchCve(ctx, CveParams)
	if errors > 0 {
		return nil, fmt.Errorf("error upserting Cves, num errors: %d", errors)
	}

	_, errors = u.upsertBatchVulnerabilities(ctx, vulnParams)
	if errors > 0 {
		return nil, fmt.Errorf("error upserting Cves, num errors: %d", errors)
	}

	return nil, nil
}

// TODO: use transactions to ensure consistency
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

// TODO: use transactions to ensure consistency
func (u *Updater) upsertBatchCve(ctx context.Context, batch []sql.BatchUpsertCveParams) (upserted, errors int) {
	if len(batch) == 0 {
		return
	}

	start := time.Now()
	var batchErr error

	u.db.BatchUpsertCve(ctx, batch).Exec(func(i int, err error) {
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

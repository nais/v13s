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
	DefaultMarkForResyncInterval        = 60 * 60 // 1 hour
	DefaultMarkUntrackedInterval        = 3 * time.Minute
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

// TODO: create a state/log table and log errors? maybe successfull and failed runs?
func (u *Updater) Run(ctx context.Context) {
	go runAtInterval(ctx, u.updateInterval, "mark and resync images", func() {
		if err := u.MarkForResync(ctx); err != nil {
			log.WithError(err).Error("Failed to mark images for resync")
			return
		}
		log.Info("resyncing images")
		if err := u.ResyncImages(ctx); err != nil {
			log.WithError(err).Error("Failed to resync images")
		}
	})

	go runAtInterval(ctx, DefaultMarkUntrackedInterval, "mark untracked images", func() {
		if err := u.db.MarkImagesAsUntracked(ctx, []sql.ImageState{
			sql.ImageStateResync,
			sql.ImageStateInitialized,
		}); err != nil {
			log.WithError(err).Error("Failed to mark images as untracked")
		}
	})
}

func runAtInterval(ctx context.Context, interval time.Duration, name string, job func()) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("job stopped")
			return
		case <-ticker.C:
			// TODO: set as debug
			log.Infof("running scheduled job '%s' at interval %v", name, interval)
			job()
		}
	}
}

// TODO: use transactions to ensure consistency
func (u *Updater) QueueImage(ctx context.Context, imageName, imageTag string) {
	go func() {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		err := u.updateForImage(ctx, imageName, imageTag)
		if err != nil {
			log.Errorf("processing image %s:%s failed: %v", imageName, imageTag, err)

			if dbErr := u.db.UpdateImageState(ctx, sql.UpdateImageStateParams{
				State: sql.ImageStateFailed,
				Name:  imageName,
				Tag:   imageTag,
			}); dbErr != nil {
				log.Errorf("failed to update image state to failed: %v", dbErr)
			}
		}
	}()
}

// ResyncImages Resync images that have state 'initialized' or 'resync'
func (u *Updater) ResyncImages(ctx context.Context) error {
	//TODO: send in states as parameter, and not use values in sql
	images, err := u.db.GetImagesScheduledForSync(ctx)
	if err != nil {
		return err
	}

	for _, image := range images {
		u.QueueImage(ctx, image.Name, image.Tag)
	}

	return nil
}

// MarkForResync Mark images for resync that have not been updated for a certain amount of time where state is not 'resync'
func (u *Updater) MarkForResync(ctx context.Context) error {
	//TODO: send in states as parameter, and not use values in sql
	err := u.db.MarkImagesForResync(
		ctx,
		sql.MarkImagesForResyncParams{
			ThresholdTime: pgtype.Timestamptz{
				Time:  time.Now().Add(-u.resyncImagesOlderThanMinutes * time.Minute),
				Valid: true,
			},
			ExcludedStates: []sql.ImageState{
				sql.ImageStateResync,
				sql.ImageStateUntracked,
				sql.ImageStateFailed,
			},
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
		return fmt.Errorf("getting project: %w", err)
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
		return nil, fmt.Errorf("upserting Cves, num errors: %d", errors)
	}

	_, errors = u.upsertBatchVulnerabilities(ctx, vulnParams)
	if errors > 0 {
		return nil, fmt.Errorf("upserting Cves, num errors: %d", errors)
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
	}).Infof("upserted batch of vulnerabilities")
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
	}).Infof("upserted batch of Cves")
	return
}

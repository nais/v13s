package updater

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
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
	source                       sources.Source
	resyncImagesOlderThanMinutes time.Duration
	updateInterval               time.Duration
}

func NewUpdater(db sql.Querier, source sources.Source, updateInterval time.Duration) *Updater {
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
			err := u.db.UpdateImageSyncStatus(ctx, sql.UpdateImageSyncStatusParams{
				ImageName:  imageName,
				ImageTag:   imageTag,
				StatusCode: "GenericError",
				Reason:     err.Error(),
				Source:     "dependencytrack",
			})
			if err != nil {
				log.Errorf("failed to update image sync status: %v", err)
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

// TODO: use transactions to ensure consistency
func (u *Updater) updateForImage(ctx context.Context, imageName, imageTag string) error {
	summary, err := u.source.GetVulnerabilitySummary(ctx, imageName, imageTag)
	if err != nil {
		if errors.Is(err, sources.ErrNoProject) {
			err := u.db.UpdateImageSyncStatus(ctx, sql.UpdateImageSyncStatusParams{
				ImageName:  imageName,
				ImageTag:   imageTag,
				StatusCode: "NotFound",
				Reason:     "project not found",
				Source:     "dependencytrack",
			})
			if err != nil {
				log.Errorf("failed to update image sync status: %v", err)
			}
			return nil
		}
		if errors.Is(err, sources.ErrNoMetrics) {
			err := u.db.UpdateImageSyncStatus(ctx, sql.UpdateImageSyncStatusParams{
				ImageName:  imageName,
				ImageTag:   imageTag,
				StatusCode: "NotFound",
				Reason:     "metrics not found",
				Source:     "dependencytrack",
			})
			if err != nil {
				log.Errorf("failed to update image sync status: %v", err)
			}
			return nil
		}
		return fmt.Errorf("getting summary: %w", err)
	}

	summaryParams := sql.UpsertVulnerabilitySummaryParams{
		ImageName:  imageName,
		ImageTag:   imageTag,
		Critical:   summary.Critical,
		High:       summary.High,
		Medium:     summary.Medium,
		Low:        summary.Low,
		Unassigned: summary.Unassigned,
		RiskScore:  summary.RiskScore,
	}

	err = u.db.UpsertVulnerabilitySummary(ctx, summaryParams)
	if err != nil {
		return err
	}

	_, err = u.updateVulnerabilities(ctx, imageName, imageTag, summary)
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

func (u *Updater) maintainSuppressedVulnerabilities(ctx context.Context, imageName string) error {
	suppressed, err := u.db.ListSuppressedVulnerabilitiesForImage(ctx, sql.ListSuppressedVulnerabilitiesForImageParams{
		ImageName: "test",
	})
	if err != nil {
		return err
	}

	for _, s := range suppressed {
		//invoke dependencytrack api and suppress
		log.Infof("checking if suppressed vulnerability %v is still suppressed", s)
	}
	return nil
}

// TODO: use transactions to ensure consistency
func (u *Updater) updateVulnerabilities(ctx context.Context, name string, tag string, summary *sources.VulnerabilitySummary) (any, error) {
	// TODO: handle suppressed vulnerabilities
	findings, err := u.source.GetVulnerabilites(ctx, summary.Id, true)
	if err != nil {
		return nil, err
	}
	cveParams := make([]sql.BatchUpsertCveParams, 0)
	vulnParams := make([]sql.BatchUpsertVulnerabilitiesParams, 0)

	for _, f := range findings {
		cveParams = append(cveParams, sql.BatchUpsertCveParams{
			CveID:    f.Cve.Id,
			CveTitle: f.Cve.Title,
			CveDesc:  f.Cve.Description,
			CveLink:  f.Cve.Link,
			Severity: f.Cve.Severity.ToInt32(),
		})
		vulnParams = append(vulnParams, sql.BatchUpsertVulnerabilitiesParams{
			ImageName: name,
			ImageTag:  tag,
			Package:   f.Package,
			CveID:     f.Cve.Id,
			Source:    u.source.Name(),
		})
	}

	// TODO: how to handle errors here?
	errs := u.batchVulns(ctx, vulnParams, cveParams)
	if len(errs) > 0 {
		for _, e := range errs {
			log.Errorf("error upserting vulnerabilities for %s: %v", name, e)
		}
	}

	return nil, nil
}

// TODO: use transactions to ensure consistency
func (u *Updater) batchVulns(ctx context.Context, vulnParams []sql.BatchUpsertVulnerabilitiesParams, cveParams []sql.BatchUpsertCveParams) []error {
	start := time.Now()
	errs := make([]error, 0)
	numErrs := 0
	u.db.BatchUpsertCve(ctx, cveParams).Exec(func(i int, err error) {
		if err != nil {
			errs = append(errs, err)
			numErrs++
		}
	})
	upserted := len(cveParams) - numErrs
	log.WithFields(log.Fields{
		"duration":   time.Since(start),
		"num_rows":   upserted,
		"num_errors": numErrs,
	}).Infof("upserted batch of CVEs")

	start = time.Now()
	numErrs = 0
	u.db.BatchUpsertVulnerabilities(ctx, vulnParams).Exec(func(i int, err error) {
		if err != nil {
			errs = append(errs, err)
			numErrs++
		}
	})

	upserted = len(cveParams) - numErrs
	log.WithFields(log.Fields{
		"duration":   time.Since(start),
		"num_rows":   upserted,
		"num_errors": numErrs,
	}).Infof("upserted batch of vulnerabilities")

	return errs
}

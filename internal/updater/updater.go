package updater

import (
	"context"
	"errors"
	"fmt"
	"github.com/containerd/log"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
	"github.com/sirupsen/logrus"
	"time"
)

const (
	DefaultResyncImagesOlderThanMinutes = 60 * 12 // 12 hours
	DefaultMarkUntrackedInterval        = 3 * time.Minute
	SyncErrorStatusCodeNotFound         = "NotFound"
	SyncErrorStatusCodeGenericError     = "GenericError"
)

type Updater struct {
	db                           *pgxpool.Pool
	queries                      sql.Querier
	source                       sources.Source
	resyncImagesOlderThanMinutes time.Duration
	updateInterval               time.Duration
	log                          *logrus.Entry
}

func NewUpdater(db *pgxpool.Pool, source sources.Source, updateInterval time.Duration, log *log.Entry) *Updater {
	if log == nil {
		log = logrus.NewEntry(logrus.StandardLogger())
	}

	return &Updater{
		db:                           db,
		queries:                      sql.New(db),
		source:                       source,
		resyncImagesOlderThanMinutes: DefaultResyncImagesOlderThanMinutes,
		updateInterval:               updateInterval,
		log:                          log,
	}
}

// TODO: create a state/log table and log errors? maybe successfull and failed runs?
func (u *Updater) Run(ctx context.Context) {
	go runAtInterval(ctx, u.updateInterval, "mark and resync images", u.log, func() {
		if err := u.MarkForResync(ctx); err != nil {
			u.log.WithError(err).Error("Failed to mark images for resync")
			return
		}
		u.log.Info("resyncing images")
		if err := u.ResyncImages(ctx); err != nil {
			u.log.WithError(err).Error("Failed to resync images")
		}
	})

	go runAtInterval(ctx, DefaultMarkUntrackedInterval, "mark untracked images", u.log, func() {
		if err := u.queries.MarkImagesAsUntracked(ctx, []sql.ImageState{
			sql.ImageStateResync,
			sql.ImageStateInitialized,
		}); err != nil {
			u.log.WithError(err).Error("Failed to mark images as untracked")
		}
	})
}

func runAtInterval(ctx context.Context, interval time.Duration, name string, log *logrus.Entry, job func()) {
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

// The deadlocks indicate that multiple transactions are competing for the same rows in
// UpsertVulnerabilitySummary, UpdateImageState, or BatchUpsertVulnerabilities.
// Fix: Add explicit transaction control and reduce contention by processing images sequentially instead of batching multiple updates.
// TODO: use transactions to ensure consistency
func (u *Updater) QueueImage(ctx context.Context, imageName, imageTag string) {
	go func() {
		// TODO: Fix: Increase the timeout or limit concurrency.
		ctx, cancel := context.WithTimeout(ctx, 1*time.Minute)
		defer cancel()
		err := u.updateForImage(ctx, imageName, imageTag)
		if err != nil {
			u.log.Errorf("processing image %s:%s failed", imageName, imageTag)
			if dbErr := u.queries.UpdateImageState(ctx, sql.UpdateImageStateParams{
				State: sql.ImageStateFailed,
				Name:  imageName,
				Tag:   imageTag,
			}); dbErr != nil {
				u.log.Errorf("failed to update image state to failed: %v", dbErr)
			}

			err = u.handleSyncError(ctx, imageName, imageTag, SyncErrorStatusCodeGenericError, err)
			if err != nil {
				u.log.Errorf("failed to update image sync status: %v", err)
			}
		}
	}()
}

// ResyncImages Resync images that have state 'initialized' or 'resync'
func (u *Updater) ResyncImages(ctx context.Context) error {
	//TODO: send in states as parameter, and not use values in sql
	images, err := u.queries.GetImagesScheduledForSync(ctx)
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
	err := u.queries.MarkImagesForResync(
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
		return u.handleSyncError(ctx, imageName, imageTag, SyncErrorStatusCodeNotFound, err)
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

	err = u.queries.UpsertVulnerabilitySummary(ctx, summaryParams)
	if err != nil {
		return err
	}

	_, err = u.updateVulnerabilities(ctx, imageName, imageTag, summary)
	if err != nil {
		return err
	}

	err = u.queries.UpdateImageState(ctx, sql.UpdateImageStateParams{
		State: sql.ImageStateUpdated,
		Name:  imageName,
		Tag:   imageTag,
	})

	if err != nil {
		return err
	}

	return nil
}

func (u *Updater) handleSyncError(ctx context.Context, imageName, imageTag, statusCode string, err error) error {
	updateSyncParams := sql.UpdateImageSyncStatusParams{
		ImageName:  imageName,
		ImageTag:   imageTag,
		StatusCode: statusCode,
		Source:     u.source.Name(),
	}

	switch {
	case errors.Is(err, sources.ErrNoProject):
		updateSyncParams.Reason = "no project found"
	case errors.Is(err, sources.ErrNoMetrics):
		updateSyncParams.Reason = "no metrics found"
	default:
		updateSyncParams.Reason = err.Error()
		u.log.Errorf("orginal error status: %v", err)
	}

	// Use a new context with a timeout to avoid failing due to an expired parent context
	newCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if insertErr := u.queries.UpdateImageSyncStatus(newCtx, updateSyncParams); insertErr != nil {
		u.log.Errorf("failed to update image sync status: %v", insertErr)
		return fmt.Errorf("updating image sync status: %w", insertErr)
	}

	return nil
}

func (u *Updater) maintainSuppressedVulnerabilities(ctx context.Context, imageName string) error {
	suppressed, err := u.queries.ListSuppressedVulnerabilitiesForImage(ctx, sql.ListSuppressedVulnerabilitiesForImageParams{
		ImageName: imageName,
	})
	if err != nil {
		return err
	}

	for _, s := range suppressed {
		//invoke dependencytrack api and suppress
		u.log.Infof("checking if suppressed vulnerability %v is still suppressed", s)
	}
	return nil
}

// TODO: use transactions to ensure consistency
func (u *Updater) updateVulnerabilities(ctx context.Context, name string, tag string, summary *sources.VulnerabilitySummary) (any, error) {
	// TODO: handle suppressed vulnerabilities
	findings, err := u.source.GetVulnerabilities(ctx, summary.Id, true)
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
			Refs:     f.Cve.References,
		})
		vulnParams = append(vulnParams, sql.BatchUpsertVulnerabilitiesParams{
			ImageName:     name,
			ImageTag:      tag,
			Package:       f.Package,
			CveID:         f.Cve.Id,
			Source:        u.source.Name(),
			LatestVersion: f.LatestVersion,
		})
	}

	// TODO: how to handle errors here?
	errs := u.batchVulns(ctx, vulnParams, cveParams, name)
	if len(errs) > 0 {
		for _, e := range errs {
			u.log.Errorf("error upserting vulnerabilities for %s: %v", name, e)
		}
		return nil, fmt.Errorf("upserting vulnerabilities, num errors: %d", len(errs))
	}

	return nil, nil
}

// TODO: use transactions to ensure consistency
func (u *Updater) batchVulns(ctx context.Context, vulnParams []sql.BatchUpsertVulnerabilitiesParams, cveParams []sql.BatchUpsertCveParams, name string) []error {
	start := time.Now()
	errs := make([]error, 0)
	numErrs := 0
	u.queries.BatchUpsertCve(ctx, cveParams).Exec(func(i int, err error) {
		if err != nil {
			errs = append(errs, err)
			numErrs++
		}
	})
	upserted := len(cveParams) - numErrs
	u.log.WithFields(log.Fields{
		"duration":   time.Since(start),
		"num_rows":   upserted,
		"num_errors": numErrs,
		"image":      name,
	}).Debug("upserted batch of CVEs")

	start = time.Now()
	numErrs = 0
	u.queries.BatchUpsertVulnerabilities(ctx, vulnParams).Exec(func(i int, err error) {
		if err != nil {
			errs = append(errs, err)
			numErrs++
		}
	})

	upserted = len(cveParams) - numErrs
	u.log.WithFields(log.Fields{
		"duration":   time.Since(start),
		"num_rows":   upserted,
		"num_errors": numErrs,
		"image":      name,
	}).Debug("upserted batch of vulnerabilities")

	return errs
}

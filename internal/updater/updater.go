package updater

import (
	"context"
	"fmt"
	"github.com/containerd/log"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"time"
)

const (
	DefaultResyncImagesOlderThanMinutes = 60 * 12 // 12 hours
	DefaultMarkUntrackedInterval        = 10 * time.Minute
	SyncErrorStatusCodeNotFound         = "NotFound"
	SyncErrorStatusCodeGenericError     = "GenericError"
)

type Updater struct {
	db                           *pgxpool.Pool
	querier                      *sql.Queries
	source                       sources.Source
	resyncImagesOlderThanMinutes time.Duration
	updateInterval               time.Duration
	log                          *logrus.Entry
}

func NewUpdater(pool *pgxpool.Pool, source sources.Source, updateInterval time.Duration, log *log.Entry) *Updater {
	if log == nil {
		log = logrus.NewEntry(logrus.StandardLogger())
	}

	_, err := pool.Exec(context.Background(), "SET statement_timeout = '5min'")
	if err != nil {
		log.WithError(err).Error("Failed to set statement_timeout")
	}

	return &Updater{
		db:                           pool,
		querier:                      sql.New(pool),
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
		if err := u.querier.MarkImagesAsUntracked(ctx, []sql.ImageState{
			sql.ImageStateResync,
			sql.ImageStateInitialized,
		}); err != nil {
			u.log.WithError(err).Error("Failed to mark images as untracked")
		}
	})
}

// ResyncImages Resync images that have state 'initialized' or 'resync'
func (u *Updater) ResyncImages(ctx context.Context) error {
	//TODO: send in states as parameter, and not use values in sql
	images, err := u.querier.GetImagesScheduledForSync(ctx)
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
	err := u.querier.MarkImagesForResync(
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

func (u *Updater) QueueImage(ctx context.Context, imageName, imageTag string) {
	var g errgroup.Group
	g.SetLimit(10) // limit to 10 concurrent goroutines

	g.Go(func() error {
		ctxTimeout, cancel := context.WithTimeout(ctx, 4*time.Minute)
		defer cancel()

		ctxTimeout = NewDbContext(ctxTimeout, u.db, u.log)
		querier := db(ctx).querier

		return SyncImage(ctxTimeout, imageName, imageTag, u.source.Name(), func(ctx context.Context) error {
			u.log.Debug("update image")
			err := u.updateVulnerabilities(ctx, imageName, imageTag)
			if err != nil {
				return err
			}

			summary, err := u.source.GetVulnerabilitySummary(ctx, imageName, imageTag)
			if err != nil {
				return err
			}

			u.log.Debug("Got summary", summary)
			err = querier.UpsertVulnerabilitySummary(ctx, sql.UpsertVulnerabilitySummaryParams{
				ImageName:  imageName,
				ImageTag:   imageTag,
				Critical:   summary.Critical,
				High:       summary.High,
				Medium:     summary.Medium,
				Low:        summary.Low,
				Unassigned: summary.Unassigned,
				RiskScore:  summary.RiskScore,
			})
			if err != nil {
				return err
			}
			u.log.Debug("upserted vulnerability summary")

			return nil
		})
	})
}

func vulnerabilitySuppressReasonToState(reason sql.VulnerabilitySuppressReason) string {
	switch reason {
	case sql.VulnerabilitySuppressReasonFalsePositive:
		return "FALSE_POSITIVE"
	case sql.VulnerabilitySuppressReasonInTriage:
		return "IN_TRIAGE"
	case sql.VulnerabilitySuppressReasonNotAffected:
		return "NOT_AFFECTED"
	case sql.VulnerabilitySuppressReasonResolved:
		return "RESOLVED"
	default:
		return "NOT_SET"
	}
}

// TODO: use transactions to ensure consistency
func (u *Updater) updateVulnerabilities(ctx context.Context, imageName string, imageTag string) error {
	u.log.Debug("update vulnerabilities for image:", imageName)
	findings, err := u.source.GetVulnerabilities(ctx, imageName, imageTag, true)
	if err != nil {
		return err
	}

	u.log.Debug("Got findings", len(findings))
	// sync suppressed vulnerabilities
	suppressedVulns, err := u.querier.ListSuppressedVulnerabilitiesForImage(ctx, imageName)
	if err != nil {
		return err
	}

	u.log.Debug("Got suppressed vulnerabilities", len(suppressedVulns))
	filteredFindings := make([]*sources.SuppressedVulnerability, 0)
	for _, s := range suppressedVulns {
		for _, f := range findings {
			if f.Cve.Id == s.CveID && f.Package == s.Package && s.Suppressed != f.Suppressed {
				filteredFindings = append(filteredFindings, &sources.SuppressedVulnerability{
					ImageName:    imageName,
					ImageTag:     imageTag,
					CveId:        f.Cve.Id,
					Package:      f.Package,
					Suppressed:   s.Suppressed,
					Reason:       s.ReasonText,
					SuppressedBy: s.SuppressedBy,
					State:        vulnerabilitySuppressReasonToState(s.Reason),
					Metadata:     f.Metadata,
				})
			}
		}
	}

	// TODO: We have to wait for the analysis to be done before we can update summary
	err = u.source.MaintainSuppressedVulnerabilities(ctx, filteredFindings)
	if err != nil {
		return err
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
			ImageName:     imageName,
			ImageTag:      imageTag,
			Package:       f.Package,
			CveID:         f.Cve.Id,
			Source:        u.source.Name(),
			LatestVersion: f.LatestVersion,
		})
	}

	// TODO: how to handle errors here?
	u.log.Debug("batch upserting vulnerabilities")
	errs := u.batchVulns(ctx, vulnParams, cveParams, imageName)
	if len(errs) > 0 {
		for _, e := range errs {
			u.log.Errorf("error upserting vulnerabilities for %s: %v", imageName, e)
		}
		return fmt.Errorf("upserting vulnerabilities, num errors: %d", len(errs))
	}

	return nil
}

// TODO: use transactions to ensure consistency
// Still have problems with large batch sizes, eg. dolly or pim
func (u *Updater) batchVulns(ctx context.Context, vulnParams []sql.BatchUpsertVulnerabilitiesParams, cveParams []sql.BatchUpsertCveParams, name string) []error {
	start := time.Now()
	errs := make([]error, 0)
	numErrs := 0
	querier := u.querier

	querier.BatchUpsertCve(ctx, cveParams).Exec(func(i int, err error) {
		if err != nil {
			errs = append(errs, err)
			u.log.Debug("error upserting cve", err)
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
	querier.BatchUpsertVulnerabilities(ctx, vulnParams).Exec(func(i int, err error) {
		if err != nil {
			errs = append(errs, err)
			u.log.Debug("error upserting vulnz", err)
			numErrs++
		}
	})
	upserted = len(vulnParams) - numErrs
	u.log.WithFields(log.Fields{
		"duration":   time.Since(start),
		"num_rows":   upserted,
		"num_errors": numErrs,
		"image":      name,
	}).Debug("upserted batch of vulnerabilities")

	return errs
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

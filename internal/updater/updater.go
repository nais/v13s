package updater

import (
	"context"
	"fmt"
	"github.com/containerd/log"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
	"github.com/sirupsen/logrus"
	"time"
)

const (
	DefaultResyncImagesOlderThanMinutes = 60 * 12 // 12 hours
	DefaultMarkUntrackedInterval        = 10 * time.Minute
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

	ctx = NewDbContext(ctx, u.querier, u.log)

	//errchan := make(chan error)
	//defer close(errchan)
	done := make(chan bool)
	defer close(done)

	batchCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	ch := make(chan *ImageVulnerabilityData, 100)

	go func() {

		if err = u.UpdateVulnerabilityData(batchCtx, ch); err != nil {
			u.log.WithError(err).Error("Failed to batch insert image vulnerability data")
			//errchan <- err
			done <- false
		} else {
			done <- true
		}
	}()

	// will block until limit is reached
	err = u.FetchVulnerabilityDataForImages(ctx, images, 10, ch)
	if err != nil {
		u.log.WithError(err).Error("Failed to fetch vulnerability data for images")
		return err
	}

	close(ch)
	updateSuccess := <-done

	fmt.Printf("updateSuccess: %v\n", updateSuccess)
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

func (u *Updater) UpdateVulnerabilityData(ctx context.Context, ch chan *ImageVulnerabilityData) error {
	var numUpserted, numErrors int
	start := time.Now()

	for {
		batch, err := collections.ReadChannel(ctx, ch, 100)
		if err != nil {
			return err
		}

		if len(batch) == 0 {
			break
		}

		batchUpserts, batchErrors := u.upsertBatch(ctx, batch)
		numUpserted += batchUpserts
		numErrors += batchErrors
	}

	u.log.WithFields(logrus.Fields{
		"duration":   time.Since(start),
		"num_rows":   numUpserted,
		"num_errors": numErrors,
	}).Infof("vulnerability data has been updated")
	return nil
}

func (u *Updater) upsertBatch(ctx context.Context, batch []*ImageVulnerabilityData) (upserted, errors int) {
	if len(batch) == 0 {
		return
	}

	imageStates := make([]sql.BatchUpdateImageStateParams, 0)
	cves := make([]sql.BatchUpsertCveParams, 0)
	vulns := make([]sql.BatchUpsertVulnerabilitiesParams, 0)

	for _, i := range batch {
		cves = append(cves, i.ToCveSqlParams()...)
		vulns = append(vulns, i.ToVulnerabilitySqlParams()...)
		imageStates = append(imageStates, sql.BatchUpdateImageStateParams{
			State: sql.ImageStateUpdated,
			Name:  i.ImageName,
			Tag:   i.ImageTag,
		})
	}

	start := time.Now()
	var batchErr error
	u.querier.BatchUpsertCve(ctx, cves).Exec(func(i int, err error) {
		if err != nil {
			u.log.WithError(err).Debug("failed to batch upsert cves")
			batchErr = err
			errors++
		}
	})
	u.querier.BatchUpsertVulnerabilities(ctx, vulns).Exec(func(i int, err error) {
		if err != nil {
			u.log.WithError(err).Debug("failed to batch upsert vulnerabilities")
			batchErr = err
			errors++
		}
	})

	if errors == 0 {
		u.querier.BatchUpdateImageState(ctx, imageStates).Exec(func(i int, err error) {
			if err != nil {
				u.log.WithError(err).Debug("failed to batch update image state")
				batchErr = err
				errors++
			}
		})
	}

	upserted += len(cves) + len(vulns) - errors
	u.log.WithError(batchErr).WithFields(logrus.Fields{
		"duration":   time.Since(start),
		"num_rows":   upserted,
		"num_errors": errors,
	}).Infof("upserted batch")
	return
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

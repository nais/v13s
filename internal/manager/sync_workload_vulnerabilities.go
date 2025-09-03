package manager

import (
	"context"
	"fmt"
	"time"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

const (
	KindSyncWorkloadVulnerabilities                = "sync_workload_vulnerabilities"
	SyncWorkloadVulnerabilitiesScheduledWaitSecond = 3 * time.Second
)

type SyncWorkloadVulnerabilitiesJob struct {
	ImageName string `json:"image_name"`
	ImageTag  string `json:"image_tag"`
}

func (SyncWorkloadVulnerabilitiesJob) Kind() string { return KindSyncWorkloadVulnerabilities }

func (SyncWorkloadVulnerabilitiesJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: KindSyncWorkloadVulnerabilities,
		// ScheduledAt: time.Now().Add(SyncWorkloadVulnerabilitiesScheduledWaitSecond),
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: 2 * time.Minute,
		},
		MaxAttempts: 6,
	}
}

type SyncWorkloadVulnerabilitiesWorker struct {
	db  sql.Querier
	log logrus.FieldLogger
	river.WorkerDefaults[SyncWorkloadVulnerabilitiesJob]
}

func (w *SyncWorkloadVulnerabilitiesWorker) Work(ctx context.Context, job *river.Job[SyncWorkloadVulnerabilitiesJob]) error {
	start := time.Now()
	img := job.Args

	// Insert new critical workload vulnerabilities
	if err := w.db.SyncWorkloadVulnerabilitiesForImage(ctx,
		sql.SyncWorkloadVulnerabilitiesForImageParams{
			ImageName: img.ImageName,
			ImageTag:  img.ImageTag,
		}); err != nil {
		return fmt.Errorf("insert vulnerabilities failed: %w", err)
	}

	// Downgrade
	if err := w.db.DowngradeWorkloadVulnerabilitiesForImage(ctx,
		sql.DowngradeWorkloadVulnerabilitiesForImageParams{
			ImageName: img.ImageName,
			ImageTag:  img.ImageTag,
		}); err != nil {
		w.log.WithError(err).Warn("failed to downgrade workload vulnerabilities")
	}

	// Resolve
	if err := w.db.ResolveWorkloadVulnerabilitiesForImage(ctx,
		sql.ResolveWorkloadVulnerabilitiesForImageParams{
			ImageName: img.ImageName,
			ImageTag:  img.ImageTag,
		}); err != nil {
		w.log.WithError(err).Warn("failed to resolve workload vulnerabilities")
	}

	w.log.WithFields(logrus.Fields{
		"image": fmt.Sprintf("%s:%s", img.ImageName, img.ImageTag),
		"took":  time.Since(start).Seconds(),
	}).Info("workload vulnerabilities synced")

	recordOutput(ctx, JobStatusWorkloadVulnerabilitiesSynced)
	return nil
}

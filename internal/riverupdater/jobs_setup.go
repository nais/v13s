package riverupdater

import (
	"context"
	"fmt"

	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/riverupdater/riverjob"
	"github.com/nais/v13s/internal/riverupdater/riverjob/job"
	"github.com/nais/v13s/internal/riverupdater/riverjob/worker"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"
)

type workerDeps struct {
	db              sql.Querier
	source          sources.Source
	verifier        attestation.Verifier
	workloadCounter metric.Int64UpDownCounter
	log             logrus.FieldLogger
}

func setupJobsAndWorkers(
	ctx context.Context,
	cfg WorkloadManagerConfig,
	log logrus.FieldLogger,
	workloadCounter metric.Int64UpDownCounter,
) (sql.Querier, riverjob.Client, error) {
	db := sql.New(cfg.Pool)

	queues := defaultQueueConfig()

	jobClient, err := riverjob.NewClient(ctx, cfg.JobConfig, queues)
	if err != nil {
		return nil, nil, fmt.Errorf("create job client: %w", err)
	}

	registerWorkers(jobClient, workerDeps{
		db:              db,
		source:          cfg.Source,
		verifier:        cfg.Verifier,
		workloadCounter: workloadCounter,
		log:             log,
	})

	return db, jobClient, nil
}

func defaultQueueConfig() map[string]river.QueueConfig {
	return map[string]river.QueueConfig{
		job.KindAddWorkload:                     {MaxWorkers: 20},
		job.KindGetAttestation:                  {MaxWorkers: 25},
		job.KindUploadAttestation:               {MaxWorkers: 10},
		job.KindDeleteWorkload:                  {MaxWorkers: 3},
		job.KindRemoveFromSource:                {MaxWorkers: 3},
		job.KindFinalizeAttestation:             {MaxWorkers: 10},
		job.KindUpsertVulnerabilitySummaries:    {MaxWorkers: 3},
		job.KindFetchVulnerabilityDataForImages: {MaxWorkers: 3},
		job.KindFinalizeAnalysisBatch:           {MaxWorkers: 5},
		job.KindProcessVulnerabilityDataBatch:   {MaxWorkers: 3},
	}
}

func registerWorkers(jobClient riverjob.Client, deps workerDeps) {
	log := deps.log

	riverjob.AddWorker(jobClient, &worker.AddWorkloadWorker{
		Querier:   deps.db,
		JobClient: jobClient,
		Log:       log.WithField("subsystem", job.KindAddWorkload),
	})

	riverjob.AddWorker(jobClient, &worker.GetAttestationWorker{
		Querier:         deps.db,
		Verifier:        deps.verifier,
		JobClient:       jobClient,
		WorkloadCounter: deps.workloadCounter,
		Log:             log.WithField("subsystem", job.KindGetAttestation),
	})

	riverjob.AddWorker(jobClient, &worker.UploadAttestationWorker{
		Querier:   deps.db,
		Source:    deps.source,
		JobClient: jobClient,
		Log:       log.WithField("subsystem", job.KindUploadAttestation),
	})

	riverjob.AddWorker(jobClient, &worker.RemoveFromSourceWorker{
		Querier: deps.db,
		Source:  deps.source,
		Log:     log.WithField("subsystem", job.KindRemoveFromSource),
	})

	riverjob.AddWorker(jobClient, &worker.DeleteWorkloadWorker{
		Querier:   deps.db,
		Source:    deps.source,
		JobClient: jobClient,
		Log:       log.WithField("subsystem", job.KindDeleteWorkload),
	})

	riverjob.AddWorker(jobClient, &worker.FinalizeAttestationWorker{
		Querier:   deps.db,
		Source:    deps.source,
		JobClient: jobClient,
		Log:       log.WithField("subsystem", job.KindFinalizeAttestation),
	})

	riverjob.AddWorker(jobClient, &worker.UpsertVulnerabilitySummariesWorker{
		Querier: deps.db,
		Source:  deps.source,
		Log:     log.WithField("subsystem", job.KindUpsertVulnerabilitySummaries),
	})

	riverjob.AddWorker(jobClient, &worker.FetchVulnerabilityDataForImagesWorker{
		Querier:   deps.db,
		Source:    deps.source,
		JobClient: jobClient,
		Log:       log.WithField("subsystem", job.KindFetchVulnerabilityDataForImages),
	})

	riverjob.AddWorker(jobClient, &worker.FinalizeAnalysisBatchWorker{
		Source:    deps.source,
		JobClient: jobClient,
		Log:       log.WithField("subsystem", job.KindFinalizeAnalysisBatch),
	})

	riverjob.AddWorker(jobClient, &worker.ProcessVulnerabilityDataBatchWorker{
		Querier:   deps.db,
		JobClient: jobClient,
		Log:       log.WithField("subsystem", job.KindProcessVulnerabilityDataBatch),
	})
}

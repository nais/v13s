package workload

import (
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/job"
	"github.com/nais/v13s/internal/manager/updater"
	"github.com/nais/v13s/internal/sources"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"
)

func RegisterWorkers(j job.Client, deps WorkerDeps) {
	job.AddWorker(j, &AddWorkloadWorker{...})
	job.AddWorker(j, &GetAttestationWorker{...})
	job.AddWorker(j, &UploadAttestationWorker{...})
	job.AddWorker(j, &RemoveFromSourceWorker{...})
	job.AddWorker(j, &DeleteWorkloadWorker{...})
	job.AddWorker(j, &updater.FetchVulnerabilityDataWorker{...})
	job.AddWorker(j, &updater.MarkAndResyncWorker{...})
	job.AddWorker(j, &updater.MarkImagesAsUntrackedWorker{...})
	job.AddWorker(j, &updater.RefreshVulnSummaryDailyWorker{...})
}

type WorkerDeps struct {
	DB       sql.Querier
	Verifier attestation.Verifier
	Source   sources.Source
	Log      logrus.FieldLogger
	Counter  metric.Int64UpDownCounter
}


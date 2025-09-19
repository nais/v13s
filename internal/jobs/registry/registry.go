package registry

import (
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/job"
	"github.com/nais/v13s/internal/jobs"
	"github.com/nais/v13s/internal/jobs/image"
	"github.com/nais/v13s/internal/jobs/sbom"
	"github.com/nais/v13s/internal/jobs/source"
	"github.com/nais/v13s/internal/jobs/types"
	"github.com/nais/v13s/internal/jobs/workload"
	"github.com/nais/v13s/internal/sources"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"
)

func RegisterWorkers(
	jobClient job.Client,
	db sql.Querier,
	verifier attestation.Verifier,
	s sources.Source,
	m jobs.WorkloadManager,
	log *logrus.Entry,
	counter metric.Int64UpDownCounter,
) {
	job.AddWorker(jobClient, &image.FetchImageWorker{Manager: m, Querier: db, Source: s, Log: log.WithField("subsystem", types.KindFetchImage)})
	job.AddWorker(jobClient, &image.UpsertImageWorker{Querier: db, Log: log.WithField("subsystem", types.KindUpsertImage)})
	job.AddWorker(jobClient, &sbom.FinalizeAttestationWorker{Manager: m, Querier: db, Source: s, Log: log.WithField("subsystem", types.KindFinalizeAttestation)})
	job.AddWorker(jobClient, &sbom.GetAttestationWorker{Manager: m, Querier: db, Verifier: verifier, WorkloadCounter: counter, Log: log.WithField("subsystem", types.KindGetAttestation)})
	job.AddWorker(jobClient, &sbom.UploadAttestationWorker{Manager: m, Querier: db, Source: s, Log: log.WithField("subsystem", types.KindUploadAttestation)})
	job.AddWorker(jobClient, &source.RemoveFromSourceWorker{Querier: db, Source: s, Log: log.WithField("subsystem", types.KindRemoveFromSource)})
	job.AddWorker(jobClient, &workload.AddWorkloadWorker{Manager: m, Querier: db, Log: log.WithField("subsystem", types.KindAddWorkload)})
	job.AddWorker(jobClient, &workload.DeleteWorkloadWorker{Manager: m, Querier: db, Log: log.WithField("subsystem", types.KindDeleteWorkload)})
}

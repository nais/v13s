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
	"github.com/nais/v13s/internal/sources/depedencytrack"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"
)

func RegisterWorkers(jobClient job.Client, db sql.Querier, verifier attestation.Verifier, s map[string]sources.Source, m jobs.WorkloadManager, log *logrus.Entry, counter metric.Int64UpDownCounter) {
	dpSrc, ok := getSource(s, depedencytrack.SourceName, log)
	if !ok {
		return
	}

	job.AddWorker(jobClient, &image.FetchImageWorker{
		Manager: m,
		Source:  dpSrc,
		Querier: db,
		Log:     log.WithField("subsystem", types.KindFetchImage),
	})
	job.AddWorker(jobClient, &sbom.FinalizeAttestationWorker{
		Manager: m,
		Source:  dpSrc,
		Querier: db,
		Log:     log.WithField("subsystem", types.KindFinalizeAttestation),
	})
	job.AddWorker(jobClient, &sbom.UploadAttestationWorker{
		Manager: m,
		Source:  dpSrc,
		Querier: db,
		Log:     log.WithField("subsystem", types.KindUploadAttestation),
	})
	job.AddWorker(jobClient, &source.RemoveFromSourceWorker{
		Querier: db,
		Source:  dpSrc,
		Log:     log.WithField("subsystem", types.KindRemoveFromSource),
	})
	job.AddWorker(jobClient, &sbom.GetAttestationWorker{
		Manager:         m,
		Querier:         db,
		Verifier:        verifier,
		WorkloadCounter: counter,
		Log:             log.WithField("subsystem", types.KindGetAttestation),
	})
	job.AddWorker(jobClient, &image.UpsertImageWorker{
		Querier: db,
		Log:     log.WithField("subsystem", types.KindUpsertImage),
	})
	job.AddWorker(jobClient, &workload.AddWorkloadWorker{
		Manager: m,
		Querier: db,
		Log:     log.WithField("subsystem", types.KindAddWorkload),
	})
	job.AddWorker(jobClient, &workload.DeleteWorkloadWorker{
		Manager: m,
		Querier: db,
		Log:     log.WithField("subsystem", types.KindDeleteWorkload),
	})
}

func getSource(sources map[string]sources.Source, name string, log *logrus.Entry) (sources.Source, bool) {
	src, ok := sources[name]
	if !ok {
		keys := make([]string, 0, len(sources))
		for k := range sources {
			keys = append(keys, k)
		}
		log.Errorf("%s source not found, workers not registered, found sources: %v", name, keys)
	}
	return src, ok
}

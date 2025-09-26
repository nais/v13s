package image

import (
	"context"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/jobs"
	"github.com/nais/v13s/internal/jobs/output"
	"github.com/nais/v13s/internal/jobs/types"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

type FetchImageSummaryWorker struct {
	Manager jobs.WorkloadManager
	Source  sources.Source
	Querier sql.Querier
	Log     logrus.FieldLogger
	river.WorkerDefaults[types.FetchImageSummaryJob]
}

func (f *FetchImageSummaryWorker) Work(ctx context.Context, job *river.Job[types.FetchImageSummaryJob]) error {
	img := job.Args
	f.Log.WithFields(logrus.Fields{
		"image": img.ImageName,
		"tag":   img.ImageTag,
	}).Debug("fetching image vulnerability summary")

	summary, err := f.Source.GetVulnerabilitySummary(ctx, img.ImageName, img.ImageTag)
	if err != nil {
		return err
	}

	workloads, err := f.Querier.ListWorkloadsByImage(ctx, sql.ListWorkloadsByImageParams{
		ImageName: img.ImageName,
		ImageTag:  img.ImageTag,
	})
	if err != nil {
		return err
	}

	output.Record(ctx, output.JobStatusImageSummaryMetadataFetched)
	return f.Manager.AddJob(ctx, types.UpsertImageJob{
		Data: &types.ImageVulnerabilityData{
			ImageName:       img.ImageName,
			ImageTag:        img.ImageTag,
			Source:          f.Source.Name(),
			Vulnerabilities: job.Args.Vulnerabilities,
			Summary:         summary,
			Workloads:       workloads,
		},
	})
}

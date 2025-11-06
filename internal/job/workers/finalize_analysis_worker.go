package workers

import (
	"context"
	"fmt"

	"github.com/nais/v13s/internal/job"
	jobs "github.com/nais/v13s/internal/job/jobs"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

type FinalizeAnalysisWorker struct {
	Source    sources.Source
	JobClient job.Client
	Log       logrus.FieldLogger
	river.WorkerDefaults[jobs.FinalizeAnalysisJob]
}

func (t *FinalizeAnalysisWorker) Work(ctx context.Context, job *river.Job[jobs.FinalizeAnalysisJob]) error {
	projectID := job.Args.ProjectID
	imgName := job.Args.ImageName
	imgTag := job.Args.ImageTag

	if job.Args.ProcessToken == "" {
		t.Log.WithField("projectID", projectID).Warn("no process token provided, assuming analysis completed")
	}

	inProgress, err := t.Source.IsTaskInProgress(ctx, job.Args.ProcessToken)
	if err != nil {
		return fmt.Errorf("check task progress for project %s: %t", projectID, err)
	}

	if inProgress {
		return fmt.Errorf("analysis still in progress for project %s", projectID)
	}

	t.Log.WithField("projectID", projectID).Debug("analysis completed successfully")

	vulnerabilities, err := t.Source.GetVulnerabilities(ctx, imgName, imgTag, true)
	if err != nil {
		return fmt.Errorf("fetch vulnerabilities for project %s: %w", projectID, err)
	}

	t.Log.WithField("projectID", projectID).WithField("vulnerabilityCount", len(vulnerabilities)).Debug("fetched vulnerabilities for project")

	if err = t.JobClient.AddJob(ctx, &jobs.ProcessVulnerabilityDataJob{
		Batch: &sources.ImageVulnerabilityData{
			ImageName:       imgName,
			ImageTag:        imgTag,
			Source:          t.Source.Name(),
			Vulnerabilities: vulnerabilities,
		},
	}); err != nil {
		return fmt.Errorf("enqueue ProcessVulnerabilityDataJob for project %s: %w", projectID, err)
	}

	return nil
}

package worker

import (
	"context"
	"fmt"

	"github.com/nais/v13s/internal/postgresriver/riverjob"
	"github.com/nais/v13s/internal/postgresriver/riverjob/job"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

type FinalizeAnalysisWorker struct {
	Source    sources.Source
	JobClient riverjob.Client
	Log       logrus.FieldLogger
	river.WorkerDefaults[job.FinalizeAnalysisJob]
}

func (t *FinalizeAnalysisWorker) Work(ctx context.Context, j *river.Job[job.FinalizeAnalysisJob]) error {
	projectID := j.Args.ProjectID
	imgName := j.Args.ImageName
	imgTag := j.Args.ImageTag

	if j.Args.ProcessToken == "" {
		t.Log.WithField("projectID", projectID).Warn("no process token provided, assuming analysis completed")
	}

	inProgress, err := t.Source.IsTaskInProgress(ctx, j.Args.ProcessToken)
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

	if err = t.JobClient.AddJob(ctx, &job.ProcessVulnerabilityDataJob{
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

package image

import (
	"context"
	"errors"
	"fmt"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/jobs"
	"github.com/nais/v13s/internal/jobs/output"
	"github.com/nais/v13s/internal/jobs/types"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

const (
	SyncErrorStatusCodeGenericError = "GenericError"
)

type FetchImageWorker struct {
	Manager jobs.WorkloadManager
	Querier sql.Querier
	Source  sources.Source
	Log     logrus.FieldLogger
	river.WorkerDefaults[types.FetchImageJob]
}

func (f *FetchImageWorker) Work(ctx context.Context, job *river.Job[types.FetchImageJob]) error {
	img := job.Args
	f.Log.WithFields(logrus.Fields{
		"image": img.ImageName,
		"tag":   img.ImageTag,
	}).Debugf("fetching image vulnerability data")

	data, err := f.fetchVulnerabilityData(ctx, img.ImageName, img.ImageTag, f.Source)
	if err != nil {
		handleErr := f.handleError(ctx, img.ImageName, img.ImageTag, f.Source.Name(), err)
		if handleErr != nil {
			output.Record(ctx, output.JobStatusImageFetchFailed)
			return handleErr
		}

		return err
	}

	output.Record(ctx, output.JobStatusImageMetadataFetched)
	return f.Manager.AddJob(ctx, types.UpsertImageJob{Data: data})
}

func (f *FetchImageWorker) fetchVulnerabilityData(ctx context.Context, imageName string, imageTag string, source sources.Source) (*types.ImageVulnerabilityData, error) {
	vulnerabilities, err := f.Source.GetVulnerabilities(ctx, imageName, imageTag, true)
	if err != nil {
		return nil, err
	}
	f.Log.Debugf("Got %d vulnerabilities", len(vulnerabilities))

	// sync suppressed vulnerabilities
	suppressedVulns, err := f.Querier.ListSuppressedVulnerabilitiesForImage(ctx, imageName)
	if err != nil {
		return nil, err
	}

	f.Log.Debugf("Got %d suppressed vulnerabilities", len(suppressedVulns))
	filteredVulnerabilities := make([]*sources.SuppressedVulnerability, 0)
	for _, sup := range suppressedVulns {
		for _, v := range vulnerabilities {
			if v.Cve.Id == sup.CveID && v.Package == sup.Package && sup.Suppressed != v.Suppressed {
				filteredVulnerabilities = append(filteredVulnerabilities, &sources.SuppressedVulnerability{
					ImageName:    imageName,
					ImageTag:     imageTag,
					CveId:        v.Cve.Id,
					Package:      v.Package,
					Suppressed:   sup.Suppressed,
					Reason:       sup.ReasonText,
					SuppressedBy: sup.SuppressedBy,
					State:        vulnerabilitySuppressReasonToState(sup.Reason),
					Metadata:     v.Metadata,
				})
			}
		}
	}

	err = f.Source.MaintainSuppressedVulnerabilities(ctx, filteredVulnerabilities)
	if err != nil {
		return nil, err
	}

	summary, err := f.Source.GetVulnerabilitySummary(ctx, imageName, imageTag)
	if err != nil {
		return nil, err
	}

	workloads, err := f.Querier.ListWorkloadsByImage(ctx, sql.ListWorkloadsByImageParams{
		ImageName: imageName,
		ImageTag:  imageTag,
	})
	if err != nil {
		return nil, err
	}

	return &types.ImageVulnerabilityData{
		ImageName:       imageName,
		ImageTag:        imageTag,
		Source:          source.Name(),
		Vulnerabilities: vulnerabilities,
		Summary:         summary,
		Workloads:       workloads,
	}, nil
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

func (f *FetchImageWorker) handleError(ctx context.Context, imageName, imageTag string, source string, err error) error {
	updateSyncParams := sql.UpdateImageSyncStatusParams{
		ImageName: imageName,
		ImageTag:  imageTag,
		Source:    source,
	}

	switch {
	case err == nil:
		return nil
	case errors.Is(err, sources.ErrNoProject):
		output.Record(ctx, output.JobStatusImageNoProject)
		_ = f.Manager.AddJob(ctx, types.RemoveFromSourceJob{
			ImageName: imageName,
			ImageTag:  imageTag,
		})
		return nil
	case errors.Is(err, sources.ErrNoMetrics):
		output.Record(ctx, output.JobStatusImageNoMetrics)
		return nil
	}

	updateSyncParams.Reason = err.Error()
	updateSyncParams.StatusCode = SyncErrorStatusCodeGenericError
	f.Log.Debugf("orginal error status: %v", err)

	if insertErr := f.Querier.UpdateImageSyncStatus(ctx, updateSyncParams); insertErr != nil {
		f.Log.Errorf("failed to update image sync status: %v", insertErr)
		return fmt.Errorf("updating image sync status: %w", insertErr)
	}

	return err
}

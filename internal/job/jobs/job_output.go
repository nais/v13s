package jobs

import (
	"context"
	"errors"

	"github.com/nais/v13s/internal/model"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

type JobOutput struct {
	Status JobStatus `json:"status"`
}

type JobStatus = string

const (
	JobStatusSourceRefDeleteSkipped     JobStatus = "source_ref_delete_skipped"
	JobStatusInitializeWorkloadSkipped  JobStatus = "initialize_workload_skipped"
	JobStatusUnrecoverable              JobStatus = "unrecoverable"
	JobStatusSourceRefExists            JobStatus = "source_ref_exists"
	JobStatusNoAttestation              JobStatus = "no_attestation"
	JobStatusAttestationDownloaded      JobStatus = "attestation_downloaded"
	JobStatusAttestationUploaded        JobStatus = "attestation_uploaded"
	JobStatusUploadAttestationFinalized JobStatus = "upload_attestation_finalized"
	JobStatusUpdated                    JobStatus = "updated"
	JobStatusImageRemovedFromSource     JobStatus = "image_removed_from_source"
	JobStatusImageStillInUse            JobStatus = "image_still_in_use"
	JobStatusSourceRefDeleted           JobStatus = "source_ref_deleted"
	JobStatusSummariesUpdated           JobStatus = "summaries_updated"
)

func RecordOutput(ctx context.Context, status JobStatus) {
	err := river.RecordOutput(ctx, JobOutput{
		Status: status,
	})
	if err != nil {
		logrus.Error("failed to record job output: %w", err)
	}
}

func HandleJobErr(originalErr error) error {
	var uErr model.UnrecoverableError
	if errors.As(originalErr, &uErr) {
		return river.JobCancel(uErr)
	}
	return originalErr
}

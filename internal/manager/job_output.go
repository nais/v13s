package manager

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
	JobStatusAttestationDownloaded      JobStatus = "attestation_downloaded"
	JobStatusAttestationUploaded        JobStatus = "attestation_uploaded"
	JobStatusImageMetadataFetched       JobStatus = "image_metadata_fetched"
	JobStatusImageRemovedFromSource     JobStatus = "image_removed_from_source"
	JobStatusImageStillInUse            JobStatus = "image_still_in_use"
	JobStatusImageSynced                JobStatus = "image_synced"
	JobStatusInitializeWorkloadSkipped  JobStatus = "initialize_workload_skipped"
	JobStatusNoAttestation              JobStatus = "no_attestation"
	JobStatusSourceRefDeleted           JobStatus = "source_ref_deleted"
	JobStatusSourceRefDeleteSkipped     JobStatus = "source_ref_delete_skipped"
	JobStatusSourceRefExists            JobStatus = "source_ref_exists"
	JobStatusUnrecoverable              JobStatus = "unrecoverable"
	JobStatusUpdated                    JobStatus = "updated"
	JobStatusUploadAttestationFinalized JobStatus = "upload_attestation_finalized"
)

func recordOutput(ctx context.Context, status JobStatus) {
	err := river.RecordOutput(ctx, JobOutput{
		Status: status,
	})
	if err != nil {
		logrus.Error("failed to record job output: %w", err)
	}
}

func handleJobErr(originalErr error) error {
	var uErr model.UnrecoverableError
	if errors.As(originalErr, &uErr) {
		return river.JobCancel(uErr)
	}
	return originalErr
}

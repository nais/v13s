package manager

import (
	"context"
	"errors"

	"github.com/nais/v13s/internal/model"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

type JobOutput struct {
	Status    JobStatus         `json:"status"`
	Event     string            `json:"event,omitempty"`     // domain event that triggered the decision
	Decision  string            `json:"decision,omitempty"`  // what was decided (retry, cancel, upload, mark_resync, etc)
	Retryable *bool             `json:"retryable,omitempty"` // whether the job will be retried
	Details   map[string]string `json:"details,omitempty"`   // context: image, tag, token_present, etc
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
)

func recordStatusOutput(ctx context.Context, status JobStatus) {
	err := river.RecordOutput(ctx, JobOutput{
		Status: status,
	})
	if err != nil {
		logrus.Error("failed to record job output: %w", err)
	}
}

func recordStructuredOutput(ctx context.Context, out JobOutput) {
	if out.Status == "" && out.Event == "" && out.Decision == "" && len(out.Details) == 0 {
		logrus.Warn("recordStructuredOutput called with no status, event, decision, or details")
	}
	err := river.RecordOutput(ctx, out)
	if err != nil {
		logrus.WithError(err).Error("failed to record structured job output")
	}
}

func handleJobErr(originalErr error) error {
	if uErr, ok := errors.AsType[model.UnrecoverableError](originalErr); ok {
		return river.JobCancel(uErr)
	}
	return originalErr
}

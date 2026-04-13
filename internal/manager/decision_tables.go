package manager

import (
	"errors"
	"fmt"

	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/model"
	"github.com/sigstore/cosign/v3/pkg/cosign"
)

// Event is a typed outcome produced by a worker step.
// Each event maps to exactly one entry in a worker-specific decision table.
type Event string

// lookupDecision returns the decision for an event or a descriptive error if the
// table is missing that event. Workers decide whether that error should cancel
func lookupDecision[T any](table map[Event]T, event Event, tableName string) (T, error) {
	decision, ok := table[event]
	if ok {
		return decision, nil
	}

	var zero T
	return zero, fmt.Errorf("no %s decision defined for event %q: this is a bug", tableName, event)
}

const (
	// get_attestation events
	EventAttestationFound       Event = "attestation_found"
	EventNoMatchingAttestations Event = "no_matching_attestations"
	EventUnrecoverable          Event = "unrecoverable"
	EventRecoverableError       Event = "recoverable_error"
)

// Decision describes the state changes and actions to apply for a given Event.
// Workers read the Decision returned by their decision table and execute it
// mechanically — no branching logic required.
type Decision struct {
	// WorkloadState is the new workload state to persist, or nil to leave it unchanged.
	WorkloadState *sql.WorkloadState

	// ImageState is the new image state to persist, or nil to leave it unchanged.
	ImageState *sql.ImageState

	// JobStatus is recorded as the River job output. Empty means nothing is recorded.
	JobStatus JobStatus

	// CancelJob stops River from retrying by wrapping the error with river.JobCancel.
	CancelJob bool

	// EnqueueUpload triggers compression and enqueuing of an UploadAttestationJob.
	EnqueueUpload bool
}

// getAttestationDecisions is the single source of truth for get_attestation
// outcomes. To change behavior, change this table instead of adding branches in
// GetAttestationWorker.Work.
var getAttestationDecisions = map[Event]Decision{
	// Attestation was verified successfully: queue it for upload.
	EventAttestationFound: {
		JobStatus:     JobStatusAttestationDownloaded,
		EnqueueUpload: true,
	},

	// No matching attestations: mark the workload/image, then let River retry
	// according to the get_attestation job's MaxAttempts.
	EventNoMatchingAttestations: {
		WorkloadState: new(sql.WorkloadStateNoAttestation),
		ImageState:    new(sql.ImageStateFailed),
		JobStatus:     JobStatusNoAttestation,
	},

	// Unrecoverable error (e.g. 4xx from registry, invalid image ref).
	// Mark the workload/image and tell River to stop retrying.
	EventUnrecoverable: {
		WorkloadState: new(sql.WorkloadStateUnrecoverable),
		ImageState:    new(sql.ImageStateFailed),
		JobStatus:     JobStatusUnrecoverable,
		CancelJob:     true,
	},

	// Transient/network error: no state change, return the error so River retries.
	EventRecoverableError: {},
}

// classifyGetAttestationEvent turns verifier.GetAttestation output into a
// domain event. It is intentionally pure and side-effect free.
func classifyGetAttestationEvent(att *attestation.Attestation, err error) Event {
	if err == nil && att != nil {
		return EventAttestationFound
	}
	if _, ok := errors.AsType[*cosign.ErrNoMatchingAttestations](err); ok {
		return EventNoMatchingAttestations
	}
	if _, ok := errors.AsType[model.UnrecoverableError](err); ok {
		return EventUnrecoverable
	}
	return EventRecoverableError
}

const (
	// EventSourceRefAlive means the source ref exists and still points to a live project.
	EventSourceRefAlive Event = "source_ref_alive"
	// EventSourceRefStale means the source ref exists but the upstream project no longer does.
	EventSourceRefStale Event = "source_ref_stale"
	// EventSourceRefMissing means no source ref exists yet.
	EventSourceRefMissing Event = "source_ref_missing"
)

// SourceRefDecision describes the upload worker's next step after checking the
// existing source ref, if any.
type SourceRefDecision struct {
	// ResyncAndReturn updates the image to Resync, records output, and stops.
	ResyncAndReturn bool
	// DeleteStale removes a stale source ref before re-uploading.
	DeleteStale bool
	// JobStatus is recorded when ResyncAndReturn is true.
	JobStatus JobStatus
}

// sourceRefDecisions contains the outcomes for the upload worker's source-ref
// check phase.
var sourceRefDecisions = map[Event]SourceRefDecision{
	// Project is alive in the source: just mark the image for resync and return.
	EventSourceRefAlive: {
		ResyncAndReturn: true,
		JobStatus:       JobStatusSourceRefExists,
	},
	// Project is gone from the source: clean up the stale ref and re-upload.
	EventSourceRefStale: {
		DeleteStale: true,
	},
	// No source ref at all: proceed straight to upload.
	EventSourceRefMissing: {},
}

// classifySourceRefEvent turns the source-ref lookup and ProjectExists result
// into a domain event. It is intentionally pure.
func classifySourceRefEvent(sourceRefFound bool, projectExists bool) Event {
	if !sourceRefFound {
		return EventSourceRefMissing
	}
	if projectExists {
		return EventSourceRefAlive
	}
	return EventSourceRefStale
}

const (
	// EventTaskInProgress means the upstream processing job is still running.
	EventTaskInProgress Event = "task_in_progress"
	// EventTaskComplete means the upstream processing job has finished.
	EventTaskComplete Event = "task_complete"
)

// FinalizeDecision describes the finalize worker's next step after checking the
// upstream processing status.
type FinalizeDecision struct {
	// RetryLater returns a normal error so River schedules another attempt.
	RetryLater bool
	// MarkResync updates the image to Resync with a ReadyForResyncAt timestamp.
	MarkResync bool
	// EnqueueRemovals enqueues RemoveFromSourceJob for any unused refs.
	EnqueueRemovals bool
	// JobStatus is recorded on success.
	JobStatus JobStatus
}

// finalizeDecisions contains the outcomes for the finalize worker's progress
// check phase.
var finalizeDecisions = map[Event]FinalizeDecision{
	// Still running: return an error so River retries according to its schedule.
	EventTaskInProgress: {
		RetryLater: true,
	},
	// Done: persist resync state and enqueue cleanup.
	EventTaskComplete: {
		MarkResync:      true,
		EnqueueRemovals: true,
		JobStatus:       JobStatusUploadAttestationFinalized,
	},
}

// classifyFinalizeEvent turns IsTaskInProgress output into a domain event.
func classifyFinalizeEvent(inProgress bool) Event {
	if inProgress {
		return EventTaskInProgress
	}
	return EventTaskComplete
}

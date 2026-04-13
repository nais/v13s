package manager

import (
	"errors"
	"fmt"
	"testing"

	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/model"
	"github.com/sigstore/cosign/v3/pkg/cosign"
)

func TestClassifyGetAttestationEvent(t *testing.T) {
	someAtt := &attestation.Attestation{Predicate: []byte(`{}`)}

	tests := []struct {
		name    string
		att     *attestation.Attestation
		err     error
		wantEvt Event
	}{
		{
			name:    "attestation found",
			att:     someAtt,
			err:     nil,
			wantEvt: EventAttestationFound,
		},
		{
			name:    "no matching attestations",
			att:     nil,
			err:     &cosign.ErrNoMatchingAttestations{},
			wantEvt: EventNoMatchingAttestations,
		},
		{
			name:    "no matching attestations wrapped",
			att:     nil,
			err:     fmt.Errorf("wrap: %w", &cosign.ErrNoMatchingAttestations{}),
			wantEvt: EventNoMatchingAttestations,
		},
		{
			name:    "unrecoverable error",
			att:     nil,
			err:     model.ToUnrecoverableError(errors.New("permanent failure"), "attestation"),
			wantEvt: EventUnrecoverable,
		},
		{
			name:    "recoverable transient error",
			att:     nil,
			err:     errors.New("connection timeout"),
			wantEvt: EventRecoverableError,
		},
		{
			name:    "nil att with nil err is recoverable (unexpected but safe)",
			att:     nil,
			err:     nil,
			wantEvt: EventRecoverableError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyGetAttestationEvent(tc.att, tc.err)
			if got != tc.wantEvt {
				t.Errorf("classifyGetAttestationEvent() = %q, want %q", got, tc.wantEvt)
			}
		})
	}
}

func TestGetAttestationDecisions_Completeness(t *testing.T) {
	// Every known event must have a decision, no silent fall-throughs.
	allEvents := []Event{
		EventAttestationFound,
		EventNoMatchingAttestations,
		EventUnrecoverable,
		EventRecoverableError,
	}
	for _, ev := range allEvents {
		if _, ok := getAttestationDecisions[ev]; !ok {
			t.Errorf("getAttestationDecisions: missing entry for event %q", ev)
		}
	}
}

func TestGetAttestationDecisions_Correctness(t *testing.T) {
	noAttest := new(sql.WorkloadStateNoAttestation)
	unrecov := new(sql.WorkloadStateUnrecoverable)
	failed := new(sql.ImageStateFailed)

	tests := []struct {
		event             Event
		wantWorkloadState *sql.WorkloadState
		wantImageState    *sql.ImageState
		wantJobStatus     JobStatus
		wantCancel        bool
		wantEnqueueUpload bool
	}{
		{
			event:             EventAttestationFound,
			wantWorkloadState: nil,
			wantImageState:    nil,
			wantJobStatus:     JobStatusAttestationDownloaded,
			wantCancel:        false,
			wantEnqueueUpload: true,
		},
		{
			event:             EventNoMatchingAttestations,
			wantWorkloadState: noAttest,
			wantImageState:    failed,
			wantJobStatus:     JobStatusNoAttestation,
			wantCancel:        false,
			wantEnqueueUpload: false,
		},
		{
			event:             EventUnrecoverable,
			wantWorkloadState: unrecov,
			wantImageState:    failed,
			wantJobStatus:     JobStatusUnrecoverable,
			wantCancel:        true,
			wantEnqueueUpload: false,
		},
		{
			event:             EventRecoverableError,
			wantWorkloadState: nil,
			wantImageState:    nil,
			wantJobStatus:     "",
			wantCancel:        false,
			wantEnqueueUpload: false,
		},
	}

	for _, tc := range tests {
		t.Run(string(tc.event), func(t *testing.T) {
			d, ok := getAttestationDecisions[tc.event]
			if !ok {
				t.Fatalf("no decision found for event %q", tc.event)
			}

			if !workloadStateEqual(d.WorkloadState, tc.wantWorkloadState) {
				t.Errorf("WorkloadState = %v, want %v", derefWS(d.WorkloadState), derefWS(tc.wantWorkloadState))
			}
			if !imageStateEqual(d.ImageState, tc.wantImageState) {
				t.Errorf("ImageState = %v, want %v", derefIS(d.ImageState), derefIS(tc.wantImageState))
			}
			if d.JobStatus != tc.wantJobStatus {
				t.Errorf("JobStatus = %q, want %q", d.JobStatus, tc.wantJobStatus)
			}
			if d.CancelJob != tc.wantCancel {
				t.Errorf("CancelJob = %v, want %v", d.CancelJob, tc.wantCancel)
			}
			if d.EnqueueUpload != tc.wantEnqueueUpload {
				t.Errorf("EnqueueUpload = %v, want %v", d.EnqueueUpload, tc.wantEnqueueUpload)
			}
		})
	}
}

func TestLookupDecision_MissingEvent(t *testing.T) {
	_, err := lookupDecision(getAttestationDecisions, Event("missing"), "get_attestation")
	if err == nil {
		t.Fatal("expected error for missing decision")
	}
	if got, want := err.Error(), `no get_attestation decision defined for event "missing": this is a bug`; got != want {
		t.Fatalf("lookupDecision() error = %q, want %q", got, want)
	}
}

func TestClassifySourceRefEvent(t *testing.T) {
	tests := []struct {
		name           string
		sourceRefFound bool
		projectExists  bool
		wantEvt        Event
	}{
		{"no source ref", false, false, EventSourceRefMissing},
		{"source ref exists, project alive", true, true, EventSourceRefAlive},
		{"source ref exists, project gone", true, false, EventSourceRefStale},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifySourceRefEvent(tc.sourceRefFound, tc.projectExists)
			if got != tc.wantEvt {
				t.Errorf("classifySourceRefEvent() = %q, want %q", got, tc.wantEvt)
			}
		})
	}
}

func TestSourceRefDecisions_Completeness(t *testing.T) {
	allEvents := []Event{EventSourceRefAlive, EventSourceRefStale, EventSourceRefMissing}
	for _, ev := range allEvents {
		if _, ok := sourceRefDecisions[ev]; !ok {
			t.Errorf("sourceRefDecisions: missing entry for event %q", ev)
		}
	}
}

func TestSourceRefDecisions_Correctness(t *testing.T) {
	tests := []struct {
		event               Event
		wantResyncAndReturn bool
		wantDeleteStale     bool
		wantJobStatus       JobStatus
	}{
		{EventSourceRefAlive, true, false, JobStatusSourceRefExists},
		{EventSourceRefStale, false, true, ""},
		{EventSourceRefMissing, false, false, ""},
	}
	for _, tc := range tests {
		t.Run(string(tc.event), func(t *testing.T) {
			d, ok := sourceRefDecisions[tc.event]
			if !ok {
				t.Fatalf("no decision found for event %q", tc.event)
			}
			if d.ResyncAndReturn != tc.wantResyncAndReturn {
				t.Errorf("ResyncAndReturn = %v, want %v", d.ResyncAndReturn, tc.wantResyncAndReturn)
			}
			if d.DeleteStale != tc.wantDeleteStale {
				t.Errorf("DeleteStale = %v, want %v", d.DeleteStale, tc.wantDeleteStale)
			}
			if d.JobStatus != tc.wantJobStatus {
				t.Errorf("JobStatus = %q, want %q", d.JobStatus, tc.wantJobStatus)
			}
		})
	}
}

func TestClassifyFinalizeEvent(t *testing.T) {
	tests := []struct {
		name       string
		inProgress bool
		wantEvt    Event
	}{
		{"task still running", true, EventTaskInProgress},
		{"task complete", false, EventTaskComplete},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyFinalizeEvent(tc.inProgress)
			if got != tc.wantEvt {
				t.Errorf("classifyFinalizeEvent() = %q, want %q", got, tc.wantEvt)
			}
		})
	}
}

func TestFinalizeDecisions_Completeness(t *testing.T) {
	allEvents := []Event{EventTaskInProgress, EventTaskComplete}
	for _, ev := range allEvents {
		if _, ok := finalizeDecisions[ev]; !ok {
			t.Errorf("finalizeDecisions: missing entry for event %q", ev)
		}
	}
}

func TestFinalizeDecisions_Correctness(t *testing.T) {
	tests := []struct {
		event               Event
		wantRetryLater      bool
		wantMarkResync      bool
		wantEnqueueRemovals bool
		wantJobStatus       JobStatus
	}{
		{EventTaskInProgress, true, false, false, ""},
		{EventTaskComplete, false, true, true, JobStatusUploadAttestationFinalized},
	}
	for _, tc := range tests {
		t.Run(string(tc.event), func(t *testing.T) {
			d, ok := finalizeDecisions[tc.event]
			if !ok {
				t.Fatalf("no decision found for event %q", tc.event)
			}
			if d.RetryLater != tc.wantRetryLater {
				t.Errorf("RetryLater = %v, want %v", d.RetryLater, tc.wantRetryLater)
			}
			if d.MarkResync != tc.wantMarkResync {
				t.Errorf("MarkResync = %v, want %v", d.MarkResync, tc.wantMarkResync)
			}
			if d.EnqueueRemovals != tc.wantEnqueueRemovals {
				t.Errorf("EnqueueRemovals = %v, want %v", d.EnqueueRemovals, tc.wantEnqueueRemovals)
			}
			if d.JobStatus != tc.wantJobStatus {
				t.Errorf("JobStatus = %q, want %q", d.JobStatus, tc.wantJobStatus)
			}
		})
	}
}

func workloadStateEqual(a, b *sql.WorkloadState) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func imageStateEqual(a, b *sql.ImageState) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func derefWS(s *sql.WorkloadState) string {
	if s == nil {
		return "<nil>"
	}
	return string(*s)
}

func derefIS(s *sql.ImageState) string {
	if s == nil {
		return "<nil>"
	}
	return string(*s)
}

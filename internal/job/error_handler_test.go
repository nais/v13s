package job

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"

	"github.com/nais/v13s/internal/database/sql"
	mockquerier "github.com/nais/v13s/internal/mocks/Querier"
	"github.com/nais/v13s/internal/model"
	"github.com/riverqueue/river/rivertype"
	"github.com/stretchr/testify/mock"
)

func encodeGetAttestationArgs(t *testing.T, imageName, imageTag string) []byte {
	t.Helper()
	b, err := json.Marshal(struct {
		ImageName string `json:"ImageName"`
		ImageTag  string `json:"ImageTag"`
	}{ImageName: imageName, ImageTag: imageTag})
	if err != nil {
		t.Fatalf("failed to encode args: %v", err)
	}
	return b
}

func TestAttestationErrorHandler_HandleError(t *testing.T) {
	t.Run("marks image failed on final attempt", func(t *testing.T) {
		querier := mockquerier.NewMockQuerier(t)
		querier.On("UpdateImageState", mock.Anything, sql.UpdateImageStateParams{
			State: sql.ImageStateFailed,
			Name:  "docker.io/devopsfaith/krakend",
			Tag:   "2.5.1",
		}).Return(nil).Once()

		h := &attestationErrorHandler{db: querier, log: slog.Default()}

		job := &rivertype.JobRow{
			Kind:        model.JobKindGetAttestation,
			Attempt:     4,
			MaxAttempts: 4,
			EncodedArgs: encodeGetAttestationArgs(t, "docker.io/devopsfaith/krakend", "2.5.1"),
		}

		result := h.HandleError(context.Background(), job, errors.New("i/o timeout"))

		if result != nil {
			t.Errorf("expected nil ErrorHandlerResult, got %+v", result)
		}
		querier.AssertExpectations(t)
	})

	t.Run("does not update state on non-final attempt", func(t *testing.T) {
		querier := mockquerier.NewMockQuerier(t)
		// UpdateImageState should NOT be called

		h := &attestationErrorHandler{db: querier, log: slog.Default()}

		job := &rivertype.JobRow{
			Kind:        model.JobKindGetAttestation,
			Attempt:     2,
			MaxAttempts: 4,
			EncodedArgs: encodeGetAttestationArgs(t, "docker.io/devopsfaith/krakend", "2.5.1"),
		}

		result := h.HandleError(context.Background(), job, errors.New("i/o timeout"))

		if result != nil {
			t.Errorf("expected nil ErrorHandlerResult, got %+v", result)
		}
		querier.AssertNotCalled(t, "UpdateImageState")
	})

	t.Run("ignores non-get_attestation jobs on final attempt", func(t *testing.T) {
		querier := mockquerier.NewMockQuerier(t)
		// UpdateImageState should NOT be called

		h := &attestationErrorHandler{db: querier, log: slog.Default()}

		job := &rivertype.JobRow{
			Kind:        "upload_attestation",
			Attempt:     4,
			MaxAttempts: 4,
			EncodedArgs: []byte(`{}`),
		}

		result := h.HandleError(context.Background(), job, errors.New("some error"))

		if result != nil {
			t.Errorf("expected nil ErrorHandlerResult, got %+v", result)
		}
		querier.AssertNotCalled(t, "UpdateImageState")
	})
}

func TestAttestationErrorHandler_HandlePanic(t *testing.T) {
	t.Run("marks image failed on final attempt panic", func(t *testing.T) {
		querier := mockquerier.NewMockQuerier(t)
		querier.On("UpdateImageState", mock.Anything, sql.UpdateImageStateParams{
			State: sql.ImageStateFailed,
			Name:  "docker.io/devopsfaith/krakend",
			Tag:   "2.5.1",
		}).Return(nil).Once()

		h := &attestationErrorHandler{db: querier, log: slog.Default()}

		job := &rivertype.JobRow{
			Kind:        model.JobKindGetAttestation,
			Attempt:     4,
			MaxAttempts: 4,
			EncodedArgs: encodeGetAttestationArgs(t, "docker.io/devopsfaith/krakend", "2.5.1"),
		}

		result := h.HandlePanic(context.Background(), job, "something panicked", "stack trace")

		if result != nil {
			t.Errorf("expected nil ErrorHandlerResult, got %+v", result)
		}
		querier.AssertExpectations(t)
	})
}

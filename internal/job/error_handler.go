package job

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/model"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

const errorHandlerDBTimeout = 5 * time.Second

type attestationErrorHandler struct {
	db  sql.Querier
	log *slog.Logger
}

func newAttestationErrorHandler(pool *pgxpool.Pool, log *slog.Logger) river.ErrorHandler {
	return &attestationErrorHandler{
		db:  sql.New(pool),
		log: log,
	}
}

// HandleError is called by River on every failed job attempt. When a
// get_attestation job has exhausted all attempts (i.e. is about to be
// discarded), the image is marked as failed so it does not remain stuck in
// resync indefinitely.
func (h *attestationErrorHandler) HandleError(ctx context.Context, job *rivertype.JobRow, err error) *river.ErrorHandlerResult {
	if job.Kind == model.JobKindGetAttestation && job.Attempt >= job.MaxAttempts {
		h.markImageFailed(ctx, job)
	}
	return nil
}

// HandlePanic is called by River when a job panics. Same discard logic as
// HandleError applies.
func (h *attestationErrorHandler) HandlePanic(ctx context.Context, job *rivertype.JobRow, panicVal any, trace string) *river.ErrorHandlerResult {
	if job.Kind == model.JobKindGetAttestation && job.Attempt >= job.MaxAttempts {
		h.markImageFailed(ctx, job)
	}
	return nil
}

func (h *attestationErrorHandler) markImageFailed(ctx context.Context, job *rivertype.JobRow) {
	var args struct {
		ImageName string `json:"ImageName"`
		ImageTag  string `json:"ImageTag"`
	}
	if err := json.Unmarshal(job.EncodedArgs, &args); err != nil {
		h.log.Error("error_handler: failed to decode get_attestation args", "job_id", job.ID, "err", err)
		return
	}

	dbCtx, cancel := context.WithTimeout(ctx, errorHandlerDBTimeout)
	defer cancel()

	n, err := h.db.UpdateImageState(dbCtx, sql.UpdateImageStateParams{
		State: sql.ImageStateFailed,
		Name:  args.ImageName,
		Tag:   args.ImageTag,
	})
	if err != nil {
		h.log.Error("error_handler: failed to mark image as failed after get_attestation exhausted all attempts",
			"job_id", job.ID,
			"image", args.ImageName,
			"tag", args.ImageTag,
			"err", err,
		)
	} else if n == 0 {
		h.log.Warn("error_handler: UpdateImageState matched no rows, image may already be gone",
			"job_id", job.ID,
			"image", args.ImageName,
			"tag", args.ImageTag,
		)
	} else {
		h.log.Info("error_handler: marked image as failed after get_attestation exhausted all attempts",
			"job_id", job.ID,
			"image", args.ImageName,
			"tag", args.ImageTag,
		)
	}
}

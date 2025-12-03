package riverjob

import (
	"context"
	"errors"

	"github.com/nais/v13s/internal/model"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

type JobEvent struct {
	Step   string `json:"step"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type jobRecorderKey struct{}

type Recorder struct {
	Events []JobEvent `json:"events"`
}

func NewRecorder(ctx context.Context) context.Context {
	return context.WithValue(ctx, jobRecorderKey{}, &Recorder{})
}

func FromContext(ctx context.Context) *Recorder {
	rec, _ := ctx.Value(jobRecorderKey{}).(*Recorder)
	return rec
}

func (r *Recorder) Add(step, status, detail string) {
	r.Events = append(r.Events, JobEvent{
		Step:   step,
		Status: status,
		Detail: detail,
	})
}

func (r *Recorder) Flush(ctx context.Context) error {
	return river.RecordOutput(ctx, r)
}

type JobOutput struct {
	Status JobStatus `json:"status"`
}

type JobStatus = string

const (
	JobStatusSourceRefDeleteSkipped JobStatus = "source_ref_delete_skipped"
	JobStatusSummariesUpdated       JobStatus = "summaries_updated"
)

func RecordOutput(ctx context.Context, status JobStatus) {
	err := river.RecordOutput(ctx, JobOutput{
		Status: status,
	})
	if err != nil {
		logrus.WithError(err).Error("failed to record job output")
	}
}

func HandleJobErr(originalErr error) error {
	var uErr model.UnrecoverableError
	if errors.As(originalErr, &uErr) {
		return river.JobCancel(uErr)
	}
	return originalErr
}

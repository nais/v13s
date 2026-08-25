package resync

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/metrics"
	"github.com/nais/v13s/internal/model"
	"github.com/sirupsen/logrus"
)

type WorkloadEnqueuer interface {
	AddWorkload(ctx context.Context, workload *model.Workload) error
}

type Querier interface {
	SetWorkloadState(ctx context.Context, arg sql.SetWorkloadStateParams) ([]*sql.SetWorkloadStateRow, error)
	UpdateImageState(ctx context.Context, arg sql.UpdateImageStateParams) (int64, error)
}

type Updater interface {
	RunCycle(ctx context.Context) error
}

type WorkloadState string

type ImageState string

type Input struct {
	Cluster       *string
	Namespace     *string
	Workload      *string
	WorkloadType  *model.WorkloadType
	WorkloadState WorkloadState
	ImageState    *ImageState
}

type Failure struct {
	Subject string
	Reason  string
}

type Result struct {
	NumWorkloads int32
	NumFailures  int32
	Workloads    []string
	Failures     []Failure
}

type Module interface {
	Resync(ctx context.Context, input Input) (Result, error)
}

type WorkloadResyncModule struct {
	parentCtx     context.Context
	querier       Querier
	mgr           WorkloadEnqueuer
	updater       Updater
	log           logrus.FieldLogger
	recordOutcome func(metrics.WorkloadResyncOutcome)
}

func NewWorkloadResyncModule(parentCtx context.Context, querier Querier, mgr WorkloadEnqueuer, updater Updater, log logrus.FieldLogger) *WorkloadResyncModule {
	return &WorkloadResyncModule{
		parentCtx:     parentCtx,
		querier:       querier,
		mgr:           mgr,
		updater:       updater,
		log:           log,
		recordOutcome: metrics.RecordWorkloadResyncOutcome,
	}
}

func (m *WorkloadResyncModule) Resync(ctx context.Context, input Input) (result Result, err error) {
	defer func() {
		outcome := metrics.WorkloadResyncOutcomeSuccess
		switch {
		case err != nil:
			outcome = metrics.WorkloadResyncOutcomeFailed
		case result.NumWorkloads == 0:
			outcome = metrics.WorkloadResyncOutcomeNoOp
		}

		recordOutcome := m.recordOutcome
		if recordOutcome == nil {
			recordOutcome = metrics.RecordWorkloadResyncOutcome
		}
		recordOutcome(outcome)
	}()

	rows, err := m.querier.SetWorkloadState(ctx, sql.SetWorkloadStateParams{
		Cluster:      input.Cluster,
		Namespace:    input.Namespace,
		WorkloadName: input.Workload,
		WorkloadType: workloadTypePtr(input.WorkloadType),
		OldState:     sql.WorkloadState(input.WorkloadState),
		State:        sql.WorkloadStateResync,
	})
	if err != nil {
		m.log.WithError(err).Error("failed to set workload state")
		return Result{}, err
	}

	result = Result{
		Workloads: make([]string, 0, len(rows)),
	}

	type imageKey struct {
		name string
		tag  string
	}

	seenImages := make(map[imageKey]struct{})
	var imageStates []struct {
		name string
		tag  string
	}
	for _, row := range rows {
		if input.ImageState == nil {
			continue
		}
		key := imageKey{name: row.ImageName, tag: row.ImageTag}
		if _, seen := seenImages[key]; seen {
			continue
		}
		seenImages[key] = struct{}{}
		imageStates = append(imageStates, struct {
			name string
			tag  string
		}{name: row.ImageName, tag: row.ImageTag})
	}

	var errs []error
	var failures []Failure
	needsResync := false
	defer func() {
		if !needsResync {
			return
		}
		go func() {
			if runErr := m.updater.RunCycle(m.parentCtx); runErr != nil {
				m.log.WithError(runErr).Error("failed to resync images")
			}
		}()
	}()

	for _, row := range rows {
		workload := &model.Workload{
			Cluster:   row.Cluster,
			Namespace: row.Namespace,
			Name:      row.Name,
			Type:      model.WorkloadType(row.WorkloadType),
			ImageName: row.ImageName,
			ImageTag:  row.ImageTag,
		}
		workloadID := workload.String()

		if err := m.mgr.AddWorkload(ctx, workload); err != nil {
			m.log.WithError(err).Error("failed to add workload to job queue")
			failures = append(failures, Failure{
				Subject: workloadID,
				Reason:  err.Error(),
			})
			errs = append(errs, fmt.Errorf("adding workload %s: %w", workload, err))
			continue
		}

		result.Workloads = append(result.Workloads, workloadID)
	}

	if len(imageStates) > 0 {
		for _, image := range imageStates {
			if _, err := m.querier.UpdateImageState(ctx, sql.UpdateImageStateParams{
				State: sql.ImageState(*input.ImageState),
				Name:  image.name,
				Tag:   image.tag,
				ReadyForResyncAt: pgtype.Timestamptz{
					Time:  time.Now(),
					Valid: true,
				},
			}); err != nil {
				m.log.WithError(err).Error("failed to update image state")
				failures = append(failures, Failure{
					Subject: fmt.Sprintf("%s:%s", image.name, image.tag),
					Reason:  err.Error(),
				})
				errs = append(errs, fmt.Errorf("updating image %s:%s: %w", image.name, image.tag, err))
				continue
			}
			needsResync = true
		}
	}

	if len(result.Workloads) == 0 {
		m.log.Debugf("no workloads to resync")
	}

	result.NumWorkloads, err = safeIntToInt32(len(result.Workloads))
	if err != nil {
		return Result{}, err
	}
	result.NumFailures, err = safeIntToInt32(len(failures))
	if err != nil {
		return Result{}, err
	}
	result.Failures = failures

	if len(errs) > 0 {
		return result, errors.Join(errs...)
	}

	return result, nil
}

func workloadTypePtr(workloadType *model.WorkloadType) *string {
	if workloadType == nil {
		return nil
	}
	s := string(*workloadType)
	return &s
}

func safeIntToInt32(n int) (int32, error) {
	if n > math.MaxInt32 || n < math.MinInt32 {
		return 0, fmt.Errorf("integer %d overflows int32", n)
	}
	return int32(n), nil
}

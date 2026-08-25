package resync

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/model"
	"github.com/sirupsen/logrus"
)

type WorkloadEnqueuer interface {
	AddWorkload(ctx context.Context, workload *model.Workload) error
}

type Updater interface {
	RunCycle(ctx context.Context) error
}

type Input struct {
	Cluster       string
	Namespace     string
	Workload      string
	WorkloadType  *string
	WorkloadState sql.WorkloadState
	ImageState    *string
}

type Result struct {
	NumWorkloads int32
	Workloads    []string
}

type Module interface {
	Resync(ctx context.Context, input Input) (Result, error)
}

type WorkloadResyncModule struct {
	parentCtx context.Context
	querier   sql.Querier
	mgr       WorkloadEnqueuer
	updater   Updater
	log       logrus.FieldLogger
}

func NewWorkloadResyncModule(parentCtx context.Context, querier sql.Querier, mgr WorkloadEnqueuer, updater Updater, log logrus.FieldLogger) *WorkloadResyncModule {
	return &WorkloadResyncModule{
		parentCtx: parentCtx,
		querier:   querier,
		mgr:       mgr,
		updater:   updater,
		log:       log,
	}
}

func (m *WorkloadResyncModule) Resync(ctx context.Context, input Input) (Result, error) {
	cluster := input.Cluster
	namespace := input.Namespace
	workloadName := input.Workload

	rows, err := m.querier.SetWorkloadState(ctx, sql.SetWorkloadStateParams{
		Cluster:      &cluster,
		Namespace:    &namespace,
		WorkloadName: &workloadName,
		WorkloadType: input.WorkloadType,
		OldState:     input.WorkloadState,
		State:        sql.WorkloadStateResync,
	})
	if err != nil {
		m.log.WithError(err).Error("failed to set workload state")
		return Result{}, err
	}

	result := Result{
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

		if err := m.mgr.AddWorkload(ctx, workload); err != nil {
			m.log.WithError(err).Error("failed to add workload to job queue")
			errs = append(errs, fmt.Errorf("adding workload %s: %w", workload, err))
			continue
		}

		result.Workloads = append(result.Workloads,
			fmt.Sprintf("%s/%s/%s/%s", workload.Cluster, workload.Namespace, workload.Type, workload.Name))
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

	if len(errs) > 0 {
		return result, errors.Join(errs...)
	}

	return result, nil
}

func safeIntToInt32(n int) (int32, error) {
	if n > math.MaxInt32 || n < math.MinInt32 {
		return 0, fmt.Errorf("integer %d overflows int32", n)
	}
	return int32(n), nil
}

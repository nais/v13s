package workload

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/job"
	"github.com/nais/v13s/internal/kubernetes"
	"github.com/nais/v13s/internal/model"
	"github.com/nais/v13s/internal/sources"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

const maxWorkers = 100

type Service struct {
	db               sql.Querier
	pool             *pgxpool.Pool
	jobClient        job.Client
	verifier         attestation.Verifier
	src              sources.Source
	queue            *kubernetes.WorkloadEventQueue
	addDispatcher    *Dispatcher[*model.Workload]
	deleteDispatcher *Dispatcher[*model.Workload]
	workloadCounter  metric.Int64UpDownCounter
	log              logrus.FieldLogger
}

func NewService(
	ctx context.Context,
	pool *pgxpool.Pool,
	jobClient job.Client,
	verifier attestation.Verifier,
	source sources.Source,
	queue *kubernetes.WorkloadEventQueue,
	log *logrus.Entry,
) *Service {
	meter := otel.GetMeterProvider().Meter("nais_v13s_manager")
	udCounter, err := meter.Int64UpDownCounter(
		"nais_v13s_manager_resources",
		metric.WithDescription("Number of workloads managed"),
	)
	if err != nil {
		panic(err)
	}

	db := sql.New(pool)
	s := &Service{
		db:              db,
		pool:            pool,
		jobClient:       jobClient,
		verifier:        verifier,
		src:             source,
		queue:           queue,
		workloadCounter: udCounter,
		log:             log,
	}
	s.addDispatcher = NewDispatcher(workloadWorker(s.AddWorkload), queue.Updated, maxWorkers)
	s.deleteDispatcher = NewDispatcher(workloadWorker(s.DeleteWorkload), queue.Deleted, maxWorkers)
	return s
}

func (s *Service) Start(ctx context.Context) {
	s.log.Info("starting workload service")
	if err := s.jobClient.Start(ctx); err != nil {
		s.log.WithError(err).Fatal("failed to start job client")
	}
	s.addDispatcher.Start(ctx)
	s.deleteDispatcher.Start(ctx)
}

func (s *Service) Stop(ctx context.Context) error {
	return s.jobClient.Stop(ctx)
}

func workloadWorker(fn func(ctx context.Context, w *model.Workload) error) Worker[*model.Workload] {
	return func(ctx context.Context, workload *model.Workload) error {
		return fn(ctx, workload)
	}
}

func (s *Service) AddWorkload(ctx context.Context, workload *model.Workload) error {
	s.log.WithField("workload", workload).Debug("adding/updating workload")
	return s.jobClient.AddJob(ctx, &AddWorkloadJob{Workload: workload})
}

func (s *Service) DeleteWorkload(ctx context.Context, workload *model.Workload) error {
	return s.jobClient.AddJob(ctx, &DeleteWorkloadJob{Workload: workload})
}

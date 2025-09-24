package job

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/jobs/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/riverqueue/river/rivertype"
	"github.com/riverqueue/rivercontrib/otelriver"
	"github.com/sirupsen/logrus"
)

const (
	RiverMigrationVersion = 6
)

func AddWorker[T river.JobArgs](c Client, worker river.Worker[T]) {
	river.AddWorker(c.GetWorkers(), worker)
}

type Options struct {
	DbUrl         string
	WorkerOptions WorkerOptions
}

type WorkerOptions struct {
	JobDelays      map[string]time.Duration
	MaxAttempts    map[string]int
	UniqueByPeriod time.Duration
}

var DefaultWorkerOptions = WorkerOptions{
	JobDelays: map[string]time.Duration{
		types.KindFetchImageSummary:   10 * time.Second,
		types.KindFinalizeAttestation: 30 * time.Second,
	},
	MaxAttempts: map[string]int{
		types.KindFetchImageSummary:   6,
		types.KindFetchImage:          5,
		types.KindRemoveFromSource:    8,
		types.KindFinalizeAttestation: 15,
		types.KindUploadAttestation:   8,
	},
	UniqueByPeriod: 1 * time.Minute,
}

type Client interface {
	AddJob(ctx context.Context, args river.JobArgs) error
	GetWorkers() *river.Workers
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

type client struct {
	workers       *river.Workers
	riverClient   *river.Client[pgx.Tx]
	pool          *pgxpool.Pool
	workerOptions WorkerOptions
}

var _ Client = (*client)(nil)

func NewClient(ctx context.Context, jobOpts *Options, queues map[string]river.QueueConfig) (Client, error) {
	pool, err := pgxpool.New(ctx, jobOpts.DbUrl)
	if err != nil {
		return nil, err
	}

	if err := migrate(ctx, pool); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	workers := river.NewWorkers()
	riverClient, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
		Logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
		Queues:               queues,
		Workers:              workers,
		JobTimeout:           5 * time.Minute,
		RescueStuckJobsAfter: 10 * time.Minute,
		Middleware: []rivertype.Middleware{
			otelriver.NewMiddleware(nil),
		},
	})
	if err != nil {
		return nil, err
	}
	return &client{
		workers:       workers,
		pool:          pool,
		riverClient:   riverClient,
		workerOptions: jobOpts.WorkerOptions,
	}, nil
}

func (c *client) AddJob(ctx context.Context, args river.JobArgs) error {
	delay := time.Duration(0)
	if d, ok := c.workerOptions.JobDelays[args.Kind()]; ok && d > 0 {
		delay = d
	}

	maxAttempts := 3
	if ma, ok := c.workerOptions.MaxAttempts[args.Kind()]; ok && ma > 0 {
		maxAttempts = ma
	}

	insertOpts := river.InsertOpts{
		Queue:       args.Kind(),
		ScheduledAt: time.Now().Add(delay),
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: c.workerOptions.UniqueByPeriod,
		},
		MaxAttempts: maxAttempts,
	}

	tx, err := c.pool.Begin(ctx)
	if err != nil {
		return err
	}

	_, err = c.riverClient.InsertTx(ctx, tx, args, &insertOpts)
	if err != nil {
		if err = tx.Rollback(ctx); err != nil {
			return fmt.Errorf("failed to rollback transaction: %w", err)
		}
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		if err = tx.Rollback(ctx); err != nil {
			return fmt.Errorf("failed to rollback transaction: %w", err)
		}
	}
	return nil
}

func (c *client) GetWorkers() *river.Workers {
	return c.workers
}

func (c *client) Start(ctx context.Context) error {
	if err := c.riverClient.Start(ctx); err != nil {
		return fmt.Errorf("failed to start river client: %w", err)
	}
	return nil
}

func (c *client) Stop(ctx context.Context) error {
	c.pool.Close()
	return c.riverClient.Stop(ctx)
}

func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	migrator, err := rivermigrate.New(riverpgxv5.New(pool), &rivermigrate.Config{})
	if err != nil {
		return err
	}

	existingVersions, err := migrator.ExistingVersions(ctx)
	if err != nil {
		return fmt.Errorf("failed to get migrator versions: %w", err)
	}
	if !slices.ContainsFunc(existingVersions, func(migration rivermigrate.Migration) bool {
		return migration.Version == RiverMigrationVersion
	}) {
		result, err := migrator.Migrate(ctx, rivermigrate.DirectionUp, &rivermigrate.MigrateOpts{
			TargetVersion: RiverMigrationVersion,
		})
		if err != nil {
			return fmt.Errorf("failed to migrate: %v", err)
		}
		for _, version := range result.Versions {
			logrus.Infof("migrated [%s] version %d\n", strings.ToUpper(string(result.Direction)), version.Version)
		}
	}
	return nil
}

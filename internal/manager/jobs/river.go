package jobs

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
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/sirupsen/logrus"
)

type WorkerManager struct {
	client  *river.Client[pgx.Tx]
	pool    *pgxpool.Pool
	log     logrus.FieldLogger
	workers *river.Workers
}

func NewWorkerManager(ctx context.Context, dbUrl string, log logrus.FieldLogger) (*WorkerManager, error) {
	dbPool, err := pgxpool.New(ctx, dbUrl)
	if err != nil {
		return nil, err
	}

	if err := migrate(ctx, dbPool, log); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	workers := river.NewWorkers()
	riverClient, err := river.NewClient(riverpgxv5.New(dbPool), &river.Config{
		Logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
		Queues: map[string]river.QueueConfig{
			river.QueueDefault: {
				MaxWorkers: 100,
			},
		},
		JobTimeout: 30 * time.Second,
		Workers:    workers,
	})
	if err != nil {
		return nil, err
	}

	return &WorkerManager{
		client:  riverClient,
		pool:    dbPool,
		log:     log,
		workers: workers,
	}, nil
}

func (w *WorkerManager) Start(ctx context.Context) error {
	if err := w.client.Start(ctx); err != nil {
		return fmt.Errorf("failed to start river client: %w", err)
	}
	return nil
}

func AddWorker[T river.JobArgs](wmgr *WorkerManager, worker river.Worker[T]) {
	river.AddWorker(wmgr.workers, worker)
}

func (w *WorkerManager) Stop(ctx context.Context) error {
	w.pool.Close()
	return w.client.Stop(ctx)
}

func (w *WorkerManager) InsertJob(ctx context.Context, jobArgs river.JobArgs) error {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	opts := &river.InsertOpts{
		MaxAttempts: 3,
	}

	_, err = w.client.InsertTx(ctx, tx, jobArgs, opts)
	if err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}

func migrate(ctx context.Context, pool *pgxpool.Pool, log logrus.FieldLogger) error {
	migrator, err := rivermigrate.New(riverpgxv5.New(pool), &rivermigrate.Config{})
	if err != nil {
		return err
	}

	existingVersions, err := migrator.ExistingVersions(ctx)
	if err != nil {
		return fmt.Errorf("failed to get migrator versions: %w", err)
	}
	if !slices.ContainsFunc(existingVersions, func(migration rivermigrate.Migration) bool {
		return migration.Version == 6
	}) {
		result, err := migrator.Migrate(ctx, rivermigrate.DirectionUp, &rivermigrate.MigrateOpts{
			TargetVersion: 6,
		})
		if err != nil {
			return fmt.Errorf("Failed to migrate: %v\n", err)
		}
		for _, version := range result.Versions {
			log.Infof("Migrated [%s] version %d\n", strings.ToUpper(string(result.Direction)), version.Version)
		}
	}
	return nil
}

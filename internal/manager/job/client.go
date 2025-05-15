package job

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/sirupsen/logrus"
	"log/slog"
	"os"
	"slices"
	"strings"
)

const (
	RiverMigrationVersion = 6
)

func AddWorker[T river.JobArgs](c Client, worker river.Worker[T]) {
	river.AddWorker(c.GetWorkers(), worker)
}

// TODO: rename to Options ?
type Config struct {
	DbUrl  string
	Logger logrus.FieldLogger
}

type Client interface {
	AddJob(ctx context.Context, args river.JobArgs) error
	GetWorkers() *river.Workers
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

type client struct {
	workers     *river.Workers
	riverClient *river.Client[pgx.Tx]
	pool        *pgxpool.Pool
}

var _ Client = (*client)(nil)

func NewClient(ctx context.Context, cfg *Config) (Client, error) {
	pool, err := pgxpool.New(ctx, cfg.DbUrl)
	if err != nil {
		return nil, err
	}

	if err := migrate(ctx, pool, cfg.Logger); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	workers := river.NewWorkers()
	riverClient, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
		Logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
		Queues: map[string]river.QueueConfig{
			river.QueueDefault: {MaxWorkers: 100},
		},
		Workers: workers,
	})
	if err != nil {
		return nil, err
	}
	return &client{
		workers:     workers,
		pool:        pool,
		riverClient: riverClient,
	}, nil
}

func (c *client) AddJob(ctx context.Context, args river.JobArgs) error {
	tx, err := c.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func(tx pgx.Tx, ctx context.Context) {
		err := tx.Rollback(ctx)
		if err != nil {
			logrus.Errorf("failed to rollback transaction: %v", err)
		}
	}(tx, ctx)

	_, err = c.riverClient.InsertTx(ctx, tx, args, nil)
	if err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
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
		return migration.Version == RiverMigrationVersion
	}) {
		result, err := migrator.Migrate(ctx, rivermigrate.DirectionUp, &rivermigrate.MigrateOpts{
			TargetVersion: RiverMigrationVersion,
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

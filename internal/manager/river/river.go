package river

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/model"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
)

type AddWorkloadArgs struct {
	Workload *model.Workload
}

func (AddWorkloadArgs) Kind() string { return "addWorkload" }

type AddWorkLoadWorker struct {
	river.WorkerDefaults[AddWorkloadArgs]
}

func (w *AddWorkLoadWorker) Work(ctx context.Context, job *river.Job[AddWorkloadArgs]) error {
	fmt.Printf("Workload: %+v\n", job.Args.Workload)
	return nil
}

type WorkerManager struct {
	client *river.Client[pgx.Tx]
	pool   *pgxpool.Pool
}

var _ river.Worker[AddWorkloadArgs] = (*AddWorkLoadWorker)(nil)

func NewWorkerManager(ctx context.Context, dbUrl string) (*WorkerManager, error) {
	dbPool, err := pgxpool.New(ctx, dbUrl)
	if err != nil {
		return nil, err
	}

	migrator, err := rivermigrate.New(riverpgxv5.New(dbPool), &rivermigrate.Config{
		//	Schema: "river",
	})
	if err != nil {
		return nil, err
	}

	_, err = migrator.Migrate(ctx, rivermigrate.DirectionUp, &rivermigrate.MigrateOpts{
		TargetVersion: 6,
	})
	if err != nil {
		fmt.Printf("Failed to migrate: %v\n", err)
	}

	//printVersions := func(res *rivermigrate.MigrateResult) {
	//	for _, version := range res.Versions {
	//		fmt.Printf("Migrated [%s] version %d\n", strings.ToUpper(string(res.Direction)), version.Version)
	//	}
	//}
	//
	//printVersions(res)

	workers := river.NewWorkers()
	river.AddWorker(workers, &AddWorkLoadWorker{})

	riverClient, err := river.NewClient(riverpgxv5.New(dbPool), &river.Config{
		//Logger: slog.New(&slogutil.SlogMessageOnlyHandler{Level: slog.LevelWarn}),
		Queues: map[string]river.QueueConfig{
			river.QueueDefault: {MaxWorkers: 100},
		},
		//Schema:  "river",
		Workers: workers,
	})
	if err != nil {
		return nil, err
	}

	if err = riverClient.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start river client: %w", err)
	}
	return &WorkerManager{
		client: riverClient,
		pool:   dbPool,
	}, nil
}

func (w *WorkerManager) Stop(ctx context.Context) error {
	w.pool.Close()
	return w.client.Stop(ctx)
}

func (w *WorkerManager) AddWorkload(ctx context.Context, workload *model.Workload) error {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = w.client.InsertTx(ctx, tx, AddWorkloadArgs{
		Workload: workload,
	}, nil)
	if err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}

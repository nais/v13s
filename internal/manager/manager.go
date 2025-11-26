package manager

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/riverupdater/riverjob"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

type ctxKey int

const mgrKey ctxKey = iota

type Mgr struct {
	Db        *Db
	JobClient riverjob.Client
	Verifier  attestation.Verifier
	Source    sources.Source
	Logger    logrus.FieldLogger
}

type Db struct {
	Pool *pgxpool.Pool
	sql.Querier
}

func NewContext(
	ctx context.Context,
	dbPool *pgxpool.Pool,
	jobClient riverjob.Client,
	verifier attestation.Verifier,
	source sources.Source,
	logger logrus.FieldLogger,
) context.Context {
	return context.WithValue(ctx, mgrKey, &Mgr{
		Db: &Db{
			Pool:    dbPool,
			Querier: sql.New(dbPool),
		},
		JobClient: jobClient,
		Verifier:  verifier,
		Source:    source,
		Logger:    logger,
	})
}

func FromContext(ctx context.Context) *Mgr {
	return ctx.Value(mgrKey).(*Mgr)
}

func JobClient(ctx context.Context) riverjob.Client {
	mgr := FromContext(ctx)
	return mgr.JobClient
}

func AddWorker[T river.JobArgs](ctx context.Context, worker river.Worker[T]) {
	mgr := FromContext(ctx)
	riverjob.AddWorker(mgr.JobClient, worker)
}

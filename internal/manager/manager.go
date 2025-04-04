package manager

import (
	"context"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/model"
	"github.com/nais/v13s/internal/sources"
	"github.com/sirupsen/logrus"
)

type manager struct {
	db  sql.Querier
	src sources.Source
	log logrus.FieldLogger
}

type ctxKey int

const mgrKey ctxKey = iota

func NewContext(ctx context.Context, querier sql.Querier, source sources.Source, log *logrus.Entry) context.Context {
	return context.WithValue(ctx, mgrKey, &manager{
		db:  querier,
		log: log,
	})
}

// TODO: refactor name of function
func AddOrUpdateWorkload(ctx context.Context, workload *model.Workload) error {
	//m := mgr(ctx)
	// check db if update is needed, i.e. image tag changed
	// then update source with the new image tag
	mgr(ctx).log.WithField("workload", workload).Info("adding or updating workload")
	return nil
}

func DeleteWorkload(ctx context.Context, workload *model.Workload) error {
	//m := mgr(ctx)
	// delete from db and source
	mgr(ctx).log.WithField("workload", workload).Info("deleting workload")
	return nil
}

func mgr(ctx context.Context) *manager {
	return ctx.Value(mgrKey).(*manager)
}

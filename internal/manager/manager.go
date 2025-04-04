package manager

import (
	"context"

	"github.com/nais/v13s/internal/collections"
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
		src: source,
		log: log,
	})
}

// TODO: refactor name of function
func AddOrUpdateWorkloads(ctx context.Context, workloads ...*model.Workload) error {
	//m := mgr(ctx)
	// check db if update is needed, i.e. image tag changed
	// then update source with the new image tag
	for _, w := range workloads {
		mgr(ctx).log.WithField("workload", w).Debug("adding or updating workload")

		err := RegisterWorkload(ctx, w, map[string]string{})
		if err != nil {
			mgr(ctx).log.WithError(err).Error("Failed to register workload")
			return err
		}
	}
	return nil
}

func DeleteWorkloads(ctx context.Context, workloads ...*model.Workload) error {
	//m := mgr(ctx)
	// delete from db and source
	for _, w := range workloads {
		mgr(ctx).log.WithField("workload", w).Debug("deleting workload")
		err := mgr(ctx).db.DeleteWorkload(ctx, sql.DeleteWorkloadParams{
			Name:         w.Name,
			Cluster:      w.Cluster,
			Namespace:    w.Namespace,
			WorkloadType: string(w.Type),
		})
		if err != nil {
			mgr(ctx).log.WithError(err).Error("Failed to delete workload")
			return err
		}
	}
	return nil
}

// TODO: check if image tag is updated before updating
func RegisterWorkload(ctx context.Context, workload *model.Workload, metadata map[string]string) error {
	db := mgr(ctx).db
	if err := db.CreateImage(ctx, sql.CreateImageParams{
		Name:     workload.ImageName,
		Tag:      workload.ImageTag,
		Metadata: metadata,
	}); err != nil {
		mgr(ctx).log.WithError(err).Error("Failed to create image")
		return err
	}

	isPlatformImage := collections.AnyMatch([]string{
		"gcr.io/cloud-sql-connectors/cloud-sql-proxy",
		"docker.io/devopsfaith/krakend",
		"europe-north1-docker.pkg.dev/nais-io/nais/images/elector",
	}, func(e string) bool {
		return e == workload.ImageName || workload.Name == "wonderwall"
	})

	wType := workload.Type
	if isPlatformImage {
		wType = model.WorkloadTypePlatform
	}

	if err := db.UpsertWorkload(ctx, sql.UpsertWorkloadParams{
		Name:         workload.Name,
		WorkloadType: string(wType),
		Namespace:    workload.Namespace,
		Cluster:      workload.Cluster,
		ImageName:    workload.ImageName,
		ImageTag:     workload.ImageTag,
	}); err != nil {
		mgr(ctx).log.WithError(err).Error("Failed to upsert workload")
		return err
	}

	return nil
}

func mgr(ctx context.Context) *manager {
	return ctx.Value(mgrKey).(*manager)
}

package manager

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/model"
	"github.com/nais/v13s/internal/sources"
	"github.com/sirupsen/logrus"
)

type manager struct {
	db       sql.Querier
	src      sources.Source
	verifier *attestation.Verifier
	log      logrus.FieldLogger
}

type ctxKey int

const mgrKey ctxKey = iota

func NewContext(ctx context.Context, querier sql.Querier, source sources.Source, verifier *attestation.Verifier, log *logrus.Entry) context.Context {
	return context.WithValue(ctx, mgrKey, &manager{
		db:       querier,
		src:      source,
		verifier: verifier,
		log:      log,
	})
}

// TODO: refactor name of function
func AddOrUpdateWorkloads(ctx context.Context, workloads ...*model.Workload) error {
	db := mgr(ctx).db
	for _, w := range workloads {
		image, err := db.GetImage(ctx, sql.GetImageParams{
			Name: w.ImageName,
			Tag:  w.ImageTag,
		})

		if err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				mgr(ctx).log.WithError(err).Error("Failed to get image")
				return err
			}
		}

		if image != nil {
			continue
		}

		// check db if update is needed, i.e. image tag changed
		// then update source with the new image tag

		mgr(ctx).log.WithField("workload", w).Debug("adding or updating workload")
		workloadId, err := RegisterWorkload(ctx, w, map[string]string{})
		if err != nil {
			mgr(ctx).log.WithError(err).Error("Failed to register workload")
			return err
		}

		verifier := mgr(ctx).verifier
		att, err := verifier.GetAttestation(ctx, w.ImageName+":"+w.ImageTag)
		if err != nil {
			if !strings.Contains(err.Error(), attestation.ErrNoAttestation) {
				mgr(ctx).log.WithError(err).Error("Failed to get attestation")
				return err
			}
		}

		if att != nil {
			source := mgr(ctx).src

			// TODO: dependencytrack update/create
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
func RegisterWorkload(ctx context.Context, workload *model.Workload, metadata map[string]string) (*pgtype.UUID, error) {
	db := mgr(ctx).db
	if err := db.CreateImage(ctx, sql.CreateImageParams{
		Name:     workload.ImageName,
		Tag:      workload.ImageTag,
		Metadata: metadata,
	}); err != nil {
		mgr(ctx).log.WithError(err).Error("Failed to create image")
		return nil, err
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

	id, err := db.UpsertWorkload(ctx, sql.UpsertWorkloadParams{
		Name:         workload.Name,
		WorkloadType: string(wType),
		Namespace:    workload.Namespace,
		Cluster:      workload.Cluster,
		ImageName:    workload.ImageName,
		ImageTag:     workload.ImageTag,
	})

	if err != nil {
		mgr(ctx).log.WithError(err).Error("Failed to upsert workload")
		return nil, err
	}

	return &id, err
}

func mgr(ctx context.Context) *manager {
	return ctx.Value(mgrKey).(*manager)
}

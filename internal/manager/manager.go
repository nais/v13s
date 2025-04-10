package manager

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/model"
	"github.com/nais/v13s/internal/sources"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type manager struct {
	db              sql.Querier
	src             sources.Source
	verifier        *attestation.Verifier
	log             logrus.FieldLogger
	workloadCounter metric.Int64UpDownCounter
}

type ctxKey int

const mgrKey ctxKey = iota

func NewContext(ctx context.Context, querier sql.Querier, source sources.Source, verifier *attestation.Verifier, log *logrus.Entry) context.Context {
	meter := otel.GetMeterProvider().Meter("nais_v13s_manager")
	udCounter, err := meter.Int64UpDownCounter("nais_v13s_manager_resources", metric.WithDescription("Number of workloads managed by the manager"))
	if err != nil {
		panic(err)
	}

	return context.WithValue(ctx, mgrKey, &manager{
		db:              querier,
		src:             source,
		verifier:        verifier,
		log:             log,
		workloadCounter: udCounter,
	})
}

// TODO: refactor name of function
func AddOrUpdateWorkloads(ctx context.Context, workloads ...*model.Workload) error {
	db := mgr(ctx).db
	for _, w := range workloads {
		row, err := db.GetWorkload(ctx, sql.GetWorkloadParams{
			Name:         w.Name,
			Cluster:      w.Cluster,
			Namespace:    w.Namespace,
			WorkloadType: string(w.Type),
		})
		if err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				mgr(ctx).log.WithError(err).Error("Failed to get workload")
				return err
			}
		}

		if w.Name == "slsa-verde" {
			fmt.Println("found slsa-verde workload")
		}
		if row != nil && w.ImageTag == row.ImageTag {

			continue
		}

		mgr(ctx).log.WithField("workload", w).Debug("adding or updating workload")
		// TODO: add metadata to workload
		workloadId, err := RegisterWorkload(ctx, w, map[string]string{})
		if err != nil {
			mgr(ctx).log.WithError(err).Error("Failed to register workload")
			return err
		}

		verifier := mgr(ctx).verifier
		att, err := verifier.GetAttestation(ctx, w.ImageName+":"+w.ImageTag)
		if err != nil {
			if !strings.Contains(err.Error(), attestation.ErrNoAttestation) {
				mgr(ctx).log.WithError(err).Warn("Failed to get attestation")
			}
		}

		mgr(ctx).workloadCounter.Add(
			ctx,
			1,
			metric.WithAttributes(
				attribute.String("type", string(w.Type)),
				attribute.String("hasAttestation", fmt.Sprint(att != nil)),
			))

		if att != nil {
			source := mgr(ctx).src
			sw := &sources.Workload{
				Cluster:   w.Cluster,
				Namespace: w.Namespace,
				Name:      w.Name,
				Type:      string(w.Type),
				ImageName: w.ImageName,
				ImageTag:  w.ImageTag,
			}
			id, err := source.UploadSbom(ctx, sw, att)
			if err != nil {
				mgr(ctx).log.WithError(err).Error("Failed to upload sbom")
				return err
			}

			err = db.CreateSourceRef(ctx, sql.CreateSourceRefParams{
				SourceID: pgtype.UUID{
					Bytes: id,
					Valid: true,
				},
				WorkloadID: *workloadId,
				SourceType: source.Name(),
			})
		}
	}
	return nil
}

func DeleteWorkloads(ctx context.Context, workloads ...*model.Workload) error {
	for _, w := range workloads {
		mgr(ctx).log.WithField("workload", w).Debug("deleting workload")
		id, err := mgr(ctx).db.DeleteWorkload(ctx, sql.DeleteWorkloadParams{
			Name:         w.Name,
			Cluster:      w.Cluster,
			Namespace:    w.Namespace,
			WorkloadType: string(w.Type),
		})
		if err != nil {
			mgr(ctx).log.WithError(err).Error("Failed to delete workload")
			return err
		}

		refs, err := mgr(ctx).db.ListSourceRefs(ctx, sql.ListSourceRefsParams{
			WorkloadID: id,
			SourceType: mgr(ctx).src.Name(),
		})
		if err != nil {
			mgr(ctx).log.WithError(err).Error("Failed to list source refs")
			return err
		}
		for _, ref := range refs {
			sw := &sources.Workload{
				Cluster:   w.Cluster,
				Namespace: w.Namespace,
				Name:      w.Name,
				Type:      string(w.Type),
				ImageName: w.ImageName,
				ImageTag:  w.ImageTag,
			}

			// TODO: functionality that ensures that the workload is deleted from the source
			// TODO: either a table that collects workload deletion failures or a retry mechanism
			err = mgr(ctx).src.DeleteWorkload(ctx, ref.SourceID.Bytes, sw)
			if err != nil {
				mgr(ctx).log.WithError(err).Error("Failed to delete workload from source")
				return err
			}
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

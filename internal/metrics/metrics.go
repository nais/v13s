package metrics

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
	promClient "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
)

func NewMeterProvider(ctx context.Context, extraCollectors ...promClient.Collector) (*sdkmetric.MeterProvider, *sdktrace.TracerProvider, promClient.Gatherer, error) {
	res, err := newResource()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating resource: %w", err)
	}

	reg := promClient.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	allCollectors := append(extraCollectors, Collectors()...)
	for _, c := range allCollectors {
		if err := reg.Register(c); err != nil {
			return nil, nil, nil, fmt.Errorf("registering collector: %w", err)
		}
	}

	metricExporter, err := otelprom.New(
		otelprom.WithRegisterer(reg),
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating prometheus exporter: %w", err)
	}

	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(metricExporter),
	)
	otel.SetMeterProvider(meterProvider)

	var tp *sdktrace.TracerProvider
	primary := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	secondary := os.Getenv("OTEL_EXPORTER_OTLP_SECONDARY")

	if primary != "" {
		var opts []sdktrace.TracerProviderOption

		opts = append(opts, sdktrace.WithResource(
			resource.NewWithAttributes(
				semconv.SchemaURL,
				semconv.ServiceNameKey.String("v13s"),
				semconv.ServiceNamespace("nais.io"),
			),
		))

		// Primary exporter
		exp1, err := otlptrace.New(ctx,
			otlptracegrpc.NewClient(
				otlptracegrpc.WithEndpointURL(primary),
				otlptracegrpc.WithInsecure(),
			),
		)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("primary exporter: %w", err)
		}
		opts = append(opts, sdktrace.WithBatcher(exp1))

		// Optional: Secondary exporter
		if secondary != "" {
			exp2, err := otlptrace.New(ctx,
				otlptracegrpc.NewClient(
					otlptracegrpc.WithEndpointURL(secondary),
					otlptracegrpc.WithInsecure(),
				),
			)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("secondary exporter: %w", err)
			}
			opts = append(opts, sdktrace.WithBatcher(exp2))
		}

		// Build tracer provider with multiple processors
		tp = sdktrace.NewTracerProvider(opts...)
		otel.SetTracerProvider(tp)
	}

	otel.SetTextMapPropagator(propagation.TraceContext{})

	return meterProvider, tp, reg, nil
}

func newResource() (*resource.Resource, error) {
	return resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("v13s"),
			semconv.ServiceVersion("0.1.0"),
		),
	)
}

func LoadWorkloadMetrics(ctx context.Context, pool *pgxpool.Pool, log logrus.FieldLogger) error {
	db := sql.New(pool)
	rows, err := db.ListUpdatedWorkloadsWithSummaries(ctx)
	if err != nil {
		return fmt.Errorf("load workload metrics from DB: %w", err)
	}

	for _, w := range rows {
		summary := sources.VulnerabilitySummary{
			Critical:   w.Critical,
			High:       w.High,
			Medium:     w.Medium,
			Low:        w.Low,
			Unassigned: w.Unassigned,
			RiskScore:  w.RiskScore,
		}

		SetWorkloadMetrics(&sql.ListWorkloadsByImageRow{
			Cluster:   w.Cluster,
			Namespace: w.Namespace,
			Name:      w.Name,
			ImageName: w.ImageName,
			ImageTag:  w.ImageTag,
		}, &summary)
	}

	log.Infof("init %d workload metrics from database", len(rows))
	return nil
}

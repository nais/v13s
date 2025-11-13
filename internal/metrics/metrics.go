package metrics

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
	promClient "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	otelmetric "go.opentelemetry.io/otel/metric"
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

	if err = initOTelWorkloadMetrics(meterProvider); err != nil {
		return nil, nil, nil, fmt.Errorf("initializing OTel workload metrics: %w", err)
	}

	var tp *sdktrace.TracerProvider
	if _, ok := os.LookupEnv("OTEL_EXPORTER_OTLP_ENDPOINT"); ok {
		client := otlptracegrpc.NewClient()
		exp, err := otlptrace.New(ctx, client)
		if err != nil {
			log.Fatalf("failed to initialize trace exporter: %v", err)
		}

		tp = sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exp),
			sdktrace.WithResource(resource.NewWithAttributes(
				semconv.SchemaURL,
				semconv.ServiceNameKey.String("v13s"),
				semconv.ServiceNamespace("nais.io"),
			)),
		)
		otel.SetTracerProvider(tp)
	}

	otel.SetTextMapPropagator(propagation.TraceContext{})

	return meterProvider, tp, reg, nil
}

func initOTelWorkloadMetrics(mp *sdkmetric.MeterProvider) error {
	meter := mp.Meter("v13s")

	var err error

	otelWorkloadRiskScore, err = meter.Float64ObservableGauge(
		"v13s_workload_risk_score",
		otelmetric.WithDescription("Aggregated risk score of a workload, based on vulnerabilities, CVSS, and inherited risk. Higher values indicate higher risk."),
	)
	if err != nil {
		return fmt.Errorf("creating workload risk observable gauge: %w", err)
	}

	otelWorkloadVulnerabilities, err = meter.Int64ObservableGauge(
		"v13s_workload_vulnerabilities",
		otelmetric.WithDescription("Number of vulnerabilities detected in the workload, grouped by severity."),
	)
	if err != nil {
		return fmt.Errorf("creating workload vulnerabilities observable gauge: %w", err)
	}

	// Register a single callback that observes both instruments.
	_, err = meter.RegisterCallback(
		func(ctx context.Context, o otelmetric.Observer) error {
			// Iterate cached workload metrics and export them as OTel metrics.
			workloadMetricCache.Range(func(_, v any) bool {
				wm := v.(workloadMetric)

				attrs := []attribute.KeyValue{
					attribute.String("workload_cluster", wm.Cluster),
					attribute.String("workload_namespace", wm.Namespace),
					attribute.String("workload_name", wm.Name),
				}

				o.ObserveFloat64(
					otelWorkloadRiskScore,
					float64(wm.Summary.RiskScore),
					otelmetric.WithAttributes(attrs...),
				)

				for sev, count := range map[string]int32{
					"CRITICAL":   wm.Summary.Critical,
					"HIGH":       wm.Summary.High,
					"MEDIUM":     wm.Summary.Medium,
					"LOW":        wm.Summary.Low,
					"UNASSIGNED": wm.Summary.Unassigned,
				} {
					o.ObserveInt64(
						otelWorkloadVulnerabilities,
						int64(count),
						otelmetric.WithAttributes(
							append(attrs, attribute.String("severity", sev))...,
						),
					)
				}

				return true
			})

			return nil
		},
		otelWorkloadRiskScore,
		otelWorkloadVulnerabilities,
	)

	if err != nil {
		return fmt.Errorf("registering workload metrics callback: %w", err)
	}

	return nil
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

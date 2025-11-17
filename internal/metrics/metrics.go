package metrics

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/config"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
	promClient "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/push"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
)

func NewMeterProvider(ctx context.Context, cfg config.MetricConfig, c ...promClient.Collector) (*metric.MeterProvider, *sdktrace.TracerProvider, promClient.Gatherer, error) {
	res, err := newResource()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating resource: %w", err)
	}

	reg := promClient.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	metricExporter, err := prometheus.New(
		prometheus.WithRegisterer(reg),
	)

	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating prometheus exporter: %w", err)
	}
	for _, collector := range append(c, Collectors()...) {
		if err := reg.Register(collector); err != nil {
			return nil, nil, nil, fmt.Errorf("registering collector: %w", err)
		}
	}

	meterProvider := metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(metricExporter),
	)
	otel.SetMeterProvider(meterProvider)

	if cfg.PrometheusMetricsPushgatewayEndpoint != "" {
		go pushPrometheusGateWay(ctx, cfg)
	}

	// Only create a trace provider if the environment variable is set
	var tp *sdktrace.TracerProvider
	if cfg.OtelExporterOtlpEndpoint != "" {
		client := otlptracegrpc.NewClient(
			otlptracegrpc.WithEndpoint(cfg.OtelExporterOtlpEndpoint),
			otlptracegrpc.WithInsecure(),
		)
		exp, err := otlptrace.New(ctx, client)
		if err != nil {
			log.Fatalf("failed to initialize exporter: %e", err)
		}

		tp = sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exp),
			sdktrace.WithResource(
				resource.NewWithAttributes(
					semconv.SchemaURL,
					semconv.ServiceNameKey.String("v13s"),
					semconv.ServiceNamespace("nais.io"),
				)),
		)
		otel.SetTracerProvider(tp)
	}

	tc := propagation.TraceContext{}
	// Register the TraceContext propagator globally.
	otel.SetTextMapPropagator(tc)

	return meterProvider, tp, reg, nil
}

func newResource() (*resource.Resource, error) {
	return resource.Merge(resource.Default(),
		resource.NewWithAttributes(semconv.SchemaURL,
			semconv.ServiceName("v13s"),
			semconv.ServiceVersion("0.1.0"),
		))
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

func pushToGateway(cfg config.MetricConfig) error {
	return push.New(cfg.PrometheusMetricsPushgatewayEndpoint, "v13s").
		Collector(WorkloadRiskScore).
		Collector(WorkloadVulnerabilities).
		Grouping("service", "v13s").
		Push()
}

func pushPrometheusGateWay(ctx context.Context, cfg config.MetricConfig) {
	ticker := time.NewTicker(1 * time.Minute)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := pushToGateway(cfg); err != nil {
					log.Printf("failed to push metrics to Prometheus Pushgateway: %v", err)
				}
			}
		}
	}()
}

package metrics

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/config"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
	promClient "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/push"
	"github.com/prometheus/common/expfmt"
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

func NewMeterProvider(ctx context.Context, cfg config.MetricConfig, log *logrus.Entry, c ...promClient.Collector) (*sdktrace.TracerProvider, promClient.Gatherer, error) {
	res, err := newResource()
	if err != nil {
		return nil, nil, fmt.Errorf("creating resource: %w", err)
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
		return nil, nil, fmt.Errorf("creating prometheus exporter: %w", err)
	}
	for _, collector := range append(c, Collectors()...) {
		if err := reg.Register(collector); err != nil {
			return nil, nil, fmt.Errorf("registering collector: %w", err)
		}
	}

	meterProvider := metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(metricExporter),
	)
	otel.SetMeterProvider(meterProvider)

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

	return tp, reg, nil
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
	wTypes := []string{"app", "job"}

	const pageSize = 300
	offset := int32(0)

	totalRows := 0

	for {
		summaries, err := db.ListVulnerabilitySummaries(ctx, sql.ListVulnerabilitySummariesParams{
			WorkloadTypes: wTypes,
			Limit:         pageSize,
			Offset:        offset,
		})
		if err != nil {
			return fmt.Errorf("loading vulnerability summaries: %w", err)
		}

		if len(summaries) == 0 {
			break
		}

		offset += int32(len(summaries))

		totalRows += len(summaries)
		for _, row := range summaries {

			summary := sources.VulnerabilitySummary{
				Critical:   safeInt(row.Critical),
				High:       safeInt(row.High),
				Medium:     safeInt(row.Medium),
				Low:        safeInt(row.Low),
				Unassigned: safeInt(row.Unassigned),
				RiskScore:  safeInt(row.RiskScore),
			}

			SetWorkloadMetrics(&sql.Workload{
				Cluster:   row.Cluster,
				Namespace: row.Namespace,
				Name:      row.WorkloadName,
				ImageName: row.CurrentImageName,
				ImageTag:  row.CurrentImageTag,
			}, &summary)
		}
	}

	log.Infof("loaded %d workload metrics", totalRows)
	return nil
}

func safeInt(val *int32) int32 {
	if val == nil {
		return 0
	}
	return *val
}

func sizeOfPromPayload(reg promClient.Gatherer) (int, error) {
	mfs, err := reg.Gather()
	if err != nil {
		return 0, err
	}

	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeTextPlain))

	for _, mf := range mfs {
		if err := enc.Encode(mf); err != nil {
			return 0, err
		}
	}

	return buf.Len(), nil
}

func pushToGateway(cfg config.MetricConfig, reg promClient.Gatherer, log logrus.FieldLogger) error {
	size, err := sizeOfPromPayload(reg)
	if err == nil {
		log.Infof("pushing %.2f MB (%.2f KB) of metrics to Prometheus Pushgateway",
			float64(size)/(1024*1024),
			float64(size)/1024,
		)
	}

	return push.New(cfg.PrometheusMetricsPushgatewayEndpoint, "v13s").
		Collector(WorkloadVulnerabilities).
		Collector(WorkloadRiskScore).
		Grouping("service", "v13s").
		Push()
}

func PushOnce(cfg config.MetricConfig, reg promClient.Gatherer, log logrus.FieldLogger) {
	if err := pushToGateway(cfg, reg, log); err != nil {
		log.Errorf("initial metrics push failed: %v", err)
	} else {
		log.Infof("initial metrics push succeeded")
	}
}

func StartIntervalPusher(ctx context.Context, cfg config.MetricConfig, reg promClient.Gatherer, log logrus.FieldLogger) {
	ticker := time.NewTicker(cfg.PrometheusPushgatewayDuration)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := pushToGateway(cfg, reg, log); err != nil {
					log.Errorf("failed to push metrics to Prometheus Pushgateway: %v", err)
				}
			}
		}
	}()
}

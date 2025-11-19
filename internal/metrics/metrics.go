package metrics

import (
	"context"
	"fmt"
	"log"
	"strings"
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

func LoadWorkloadMetricsAndNamespaceAggregates(ctx context.Context, pool *pgxpool.Pool, log logrus.FieldLogger) error {
	db := sql.New(pool)
	wTypes := []string{"app", "job"}

	const pageSize = 300
	offset := int32(0)

	type NamespaceAggregate struct {
		Risk float64
		Sev  map[string]int
	}

	namespaceAgg := make(map[string]*NamespaceAggregate)
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

		// Break the loop if no more summaries are returned
		if len(summaries) == 0 {
			break
		}

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

			SetWorkloadMetrics(&sql.ListWorkloadsByImageRow{
				Cluster:   row.Cluster,
				Namespace: row.Namespace,
				Name:      row.WorkloadName,
				ImageName: row.CurrentImageName,
				ImageTag:  row.CurrentImageTag,
			}, &summary)

			key := row.Cluster + "/" + row.Namespace
			if _, ok := namespaceAgg[key]; !ok {
				namespaceAgg[key] = &NamespaceAggregate{
					Risk: 0,
					Sev: map[string]int{
						"CRITICAL":   0,
						"HIGH":       0,
						"MEDIUM":     0,
						"LOW":        0,
						"UNASSIGNED": 0,
					},
				}
			}

			agg := namespaceAgg[key]
			agg.Risk += float64(summary.RiskScore)
			agg.Sev["CRITICAL"] += int(summary.Critical)
			agg.Sev["HIGH"] += int(summary.High)
			agg.Sev["MEDIUM"] += int(summary.Medium)
			agg.Sev["LOW"] += int(summary.Low)
			agg.Sev["UNASSIGNED"] += int(summary.Unassigned)
		}

		offset += pageSize
	}

	for key, a := range namespaceAgg {
		parts := strings.Split(key, "/")
		cluster, ns := parts[0], parts[1]

		NamespaceRiskScore.WithLabelValues(cluster, ns).Set(a.Risk)

		for sev, count := range a.Sev {
			NamespaceVulnerabilities.
				WithLabelValues(cluster, ns, sev).Set(float64(count))
		}
	}

	log.Infof("loaded %d workload metrics; %d namespaces aggregated", totalRows, len(namespaceAgg))
	return nil
}

func safeInt(val *int32) int32 {
	if val == nil {
		return 0
	}
	return *val
}

func pushToGateway(cfg config.MetricConfig) error {
	return push.New(cfg.PrometheusMetricsPushgatewayEndpoint, "v13s").
		Collector(NamespaceVulnerabilities).
		Collector(NamespaceRiskScore).
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

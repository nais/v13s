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
	rows, err := db.ListUpdatedWorkloadsWithSummaries(ctx)
	if err != nil {
		return fmt.Errorf("load workload metrics from DB: %w", err)
	}

	type Agg struct {
		Risk float64
		Sev  map[string]int
	}

	namespaces := make(map[string]*Agg)
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

		key := w.Cluster + "/" + w.Namespace + "/" + w.Name
		if _, ok := namespaces[key]; !ok {
			namespaces[key] = &Agg{
				Sev: map[string]int{
					"CRITICAL":   0,
					"HIGH":       0,
					"MEDIUM":     0,
					"LOW":        0,
					"UNASSIGNED": 0,
				},
			}
		}

		agg := namespaces[key]
		agg.Risk += float64(w.RiskScore)

		if w.Critical > 0 {
			agg.Sev["CRITICAL"]++
		}
		if w.High > 0 {
			agg.Sev["HIGH"]++
		}
		if w.Medium > 0 {
			agg.Sev["MEDIUM"]++
		}
		if w.Low > 0 {
			agg.Sev["LOW"]++
		}
		if w.Unassigned > 0 {
			agg.Sev["UNASSIGNED"]++
		}
	}

	for key, a := range namespaces {
		parts := strings.Split(key, "/")
		cluster, ns := parts[0], parts[1]

		NamespaceRiskScore.WithLabelValues(cluster, ns).Set(a.Risk)

		for sev, count := range a.Sev {
			NamespaceVulnerabilities.
				WithLabelValues(cluster, ns, sev).
				Set(float64(count))
		}
	}

	log.Infof(
		"initialized %d workload metrics and %d namespace aggregates",
		len(rows),
		len(namespaces),
	)

	return nil
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

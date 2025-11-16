package metrics

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
	promClient "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
)

type loggingExporter struct {
	next sdktrace.SpanExporter
	log  logrus.FieldLogger
}

func (l *loggingExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	err := l.next.ExportSpans(ctx, spans)
	if err != nil {
		l.log.Errorf("OTLP EXPORT FAILED (%d spans): %v", len(spans), err)
	}
	return err
}

func (l *loggingExporter) Shutdown(ctx context.Context) error {
	return l.next.Shutdown(ctx)
}

func NewMeterProvider(ctx context.Context, log logrus.FieldLogger, extraCollectors ...promClient.Collector) (*sdkmetric.MeterProvider, *sdktrace.TracerProvider, promClient.Gatherer, error) {
	res, err := newResource()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating resource: %w", err)
	}

	reg := promClient.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	for _, c := range append(extraCollectors, Collectors()...) {
		if err := reg.Register(c); err != nil {
			return nil, nil, nil, fmt.Errorf("registering collector: %w", err)
		}
	}

	promExporter, err := otelprom.New(otelprom.WithRegisterer(reg))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating prometheus exporter: %w", err)
	}

	primary := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	secondary := os.Getenv("OTEL_EXPORTER_OTLP_SECONDARY")

	var metricOpts []sdkmetric.Option
	metricOpts = append(metricOpts, sdkmetric.WithResource(res))
	metricOpts = append(metricOpts, sdkmetric.WithReader(promExporter))

	if secondary != "" {
		var metricExp sdkmetric.Exporter
		if strings.HasPrefix(secondary, "http://") || strings.HasPrefix(secondary, "https://") {
			metricExp, err = otlpmetrichttp.New(ctx,
				otlpmetrichttp.WithEndpointURL(secondary),
			)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("create otlp http metric exporter: %w", err)
			}
		} else {
			metricExp, err = otlpmetricgrpc.New(ctx,
				otlpmetricgrpc.WithEndpoint(secondary),
				otlpmetricgrpc.WithInsecure(),
			)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("create otlp grpc metric exporter: %w", err)
			}
		}
		metricOpts = append(metricOpts, sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp)))
	}

	meterProvider := sdkmetric.NewMeterProvider(metricOpts...)
	otel.SetMeterProvider(meterProvider)

	var tp *sdktrace.TracerProvider
	if primary != "" {
		var traceOpts []sdktrace.TracerProviderOption

		traceOpts = append(traceOpts,
			sdktrace.WithResource(
				resource.NewWithAttributes(
					semconv.SchemaURL,
					semconv.ServiceNameKey.String("v13s"),
					semconv.ServiceNamespace("nais.io"),
				),
			),
		)

		exp1, err := newLoggedExporter(ctx, primary, log.WithField("otel_exporter", "primary"))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("primary exporter: %w", err)
		}
		traceOpts = append(traceOpts, sdktrace.WithBatcher(exp1))

		if secondary != "" {
			exp2, err := newLoggedExporter(ctx, secondary, log.WithField("otel_exporter", "secondary"))
			if err != nil {
				return nil, nil, nil, fmt.Errorf("secondary exporter: %w", err)
			}
			traceOpts = append(traceOpts, sdktrace.WithBatcher(exp2))
		}

		tp = sdktrace.NewTracerProvider(traceOpts...)
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

func newLoggedExporter(ctx context.Context, endpoint string, log logrus.FieldLogger) (sdktrace.SpanExporter, error) {
	log.Infof("Initializing OTLP exporter for endpoint: %s", endpoint)

	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		exp, err := otlptrace.New(ctx,
			otlptracehttp.NewClient(
				otlptracehttp.WithEndpointURL(endpoint),
			),
		)
		if err != nil {
			log.Errorf("failed creating OTLP HTTP exporter for '%s': %v", endpoint, err)
			return nil, err
		}

		log.Infof("OTLP HTTP exporter connected to %s", endpoint)
		return &loggingExporter{next: exp, log: log}, nil
	}

	exp, err := otlptrace.New(ctx,
		otlptracegrpc.NewClient(
			otlptracegrpc.WithEndpoint(endpoint),
			otlptracegrpc.WithInsecure(),
		),
	)
	if err != nil {
		log.Errorf("failed creating OTLP gRPC exporter for '%s': %v", endpoint, err)
		return nil, err
	}

	log.Infof("OTLP gRPC exporter connected to %s", endpoint)
	return &loggingExporter{next: exp, log: log}, nil
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

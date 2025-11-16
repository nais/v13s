package metrics

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
	prom "github.com/prometheus/client_golang/prometheus"
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

func NewMeterProvider(ctx context.Context, extra ...prom.Collector) (*sdkmetric.MeterProvider, *sdktrace.TracerProvider, prom.Gatherer, error) {
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName("v13s"),
			semconv.ServiceVersion("0.1.0"),
		),
	)
	if err != nil {
		return nil, nil, nil, err
	}

	reg := prom.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	for _, c := range extra {
		reg.MustRegister(c)
	}

	promExporter, err := otelprom.New(otelprom.WithRegisterer(reg))
	if err != nil {
		return nil, nil, nil, err
	}

	primary := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	secondary := os.Getenv("OTEL_EXPORTER_OTLP_SECONDARY")

	var metricOpts []sdkmetric.Option
	metricOpts = append(metricOpts, sdkmetric.WithResource(res))
	metricOpts = append(metricOpts, sdkmetric.WithReader(promExporter))

	if secondary != "" {
		if strings.HasPrefix(secondary, "https://") {
			exp, err := otlpmetrichttp.New(ctx, otlpmetrichttp.WithEndpointURL(secondary))
			if err != nil {
				return nil, nil, nil, fmt.Errorf("OTLP http metric exporter: %w", err)
			}
			metricOpts = append(metricOpts, sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp)))
		} else {
			exp, err := otlpmetricgrpc.New(ctx,
				otlpmetricgrpc.WithEndpoint(secondary),
				otlpmetricgrpc.WithInsecure(),
			)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("OTLP grpc metric exporter: %w", err)
			}
			metricOpts = append(metricOpts, sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp)))
		}
	}

	meterProvider := sdkmetric.NewMeterProvider(metricOpts...)
	otel.SetMeterProvider(meterProvider)

	if err := InitOTelMetrics(meterProvider.Meter("v13s")); err != nil {
		return nil, nil, nil, err
	}

	var tp *sdktrace.TracerProvider
	if primary != "" {

		var traceOpts []sdktrace.TracerProviderOption

		traceOpts = append(traceOpts,
			sdktrace.WithResource(res),
		)

		exp1, err := newTraceExporter(ctx, primary)
		if err != nil {
			return nil, nil, nil, err
		}
		traceOpts = append(traceOpts, sdktrace.WithBatcher(exp1))

		if secondary != "" {
			exp2, err := newTraceExporter(ctx, secondary)
			if err != nil {
				return nil, nil, nil, err
			}
			traceOpts = append(traceOpts, sdktrace.WithBatcher(exp2))
		}

		tp = sdktrace.NewTracerProvider(traceOpts...)
		otel.SetTracerProvider(tp)
	}

	otel.SetTextMapPropagator(propagation.TraceContext{})
	return meterProvider, tp, reg, nil
}

func newTraceExporter(ctx context.Context, endpoint string) (sdktrace.SpanExporter, error) {
	if strings.HasPrefix(endpoint, "https://") {
		return otlptrace.New(ctx,
			otlptracehttp.NewClient(
				otlptracehttp.WithEndpointURL(endpoint),
			),
		)
	}
	return otlptrace.New(ctx,
		otlptracegrpc.NewClient(
			otlptracegrpc.WithEndpoint(endpoint),
			otlptracegrpc.WithInsecure(),
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

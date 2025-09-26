package metrics

import (
	"context"
	"fmt"
	"log"
	"os"

	promClient "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
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

func NewMeterProvider(ctx context.Context) (*metric.MeterProvider, *sdktrace.TracerProvider, promClient.Gatherer, error) {
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
	for _, collector := range Collectors() {
		if err := reg.Register(collector); err != nil {
			return nil, nil, nil, fmt.Errorf("registering collector: %w", err)
		}
	}

	meterProvider := metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(metricExporter),
	)
	otel.SetMeterProvider(meterProvider)

	// Only create a trace provider if the environment variable is set
	var tp *sdktrace.TracerProvider
	if _, ok := os.LookupEnv("OTEL_EXPORTER_OTLP_ENDPOINT"); ok {
		client := otlptracegrpc.NewClient()
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

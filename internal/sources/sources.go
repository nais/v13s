package sources

import (
	"context"
	"fmt"

	"github.com/nais/v13s/internal/sources/source"
	"github.com/sirupsen/logrus"
)

type SourceConfig interface {
	GetUrl() string
	Type() string
}

type Source interface {
	Delete(ctx context.Context, imageName string, imageTag string) error
	GetVulnerabilities(ctx context.Context, imageName, imageTag string, includeSuppressed bool) ([]*source.Vulnerability, error)
	GetVulnerabilitySummary(ctx context.Context, imageName, imageTag string) (*source.VulnerabilitySummary, error)
	IsTaskInProgress(ctx context.Context, processToken string) (bool, error)
	MaintainSuppressedVulnerabilities(ctx context.Context, suppressed []*source.SuppressedVulnerability) error
	Name() string
	ProjectExists(ctx context.Context, imageName, imageTag string) (bool, error)
	UploadAttestation(ctx context.Context, imageName string, imageTag string, att []byte) (*source.UploadAttestationResponse, error)
}

type SourceFactory func(cfg SourceConfig, log logrus.FieldLogger) (Source, error)

var factories = map[string]SourceFactory{}

func RegisterSource(name string, f SourceFactory) {
	factories[name] = f
}

func New(cfg SourceConfig, log logrus.FieldLogger) (Source, error) {
	if f, ok := factories[cfg.Type()]; ok {
		return f(cfg, log)
	}
	return nil, fmt.Errorf("unsupported source config type: %T", cfg)
}

func SetupSources(configs []SourceConfig, log logrus.FieldLogger) (map[string]Source, error) {
	sourcesMap := make(map[string]Source)
	for _, cfg := range configs {
		s, err := New(cfg, log)
		if err != nil {
			return nil, err
		}
		name := s.Name()
		if _, exists := sourcesMap[name]; exists {
			log.Warnf("duplicate source with name '%s', overwriting", name)
		}
		sourcesMap[name] = s
	}
	return sourcesMap, nil
}

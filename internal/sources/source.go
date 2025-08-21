package sources

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/nais/dependencytrack/pkg/dependencytrack"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

type SourceConfig interface {
	GetUrl() string
}

type DependencyTrackConfig struct {
	Url      string `envconfig:"DEPENDENCYTRACK_URL"`
	Username string `envconfig:"DEPENDENCYTRACK_USERNAME" default:"v13s"`
	Password string `envconfig:"DEPENDENCYTRACK_PASSWORD"`
}

func (d DependencyTrackConfig) GetUrl() string {
	return d.Url
}

var _ SourceConfig = &DependencyTrackConfig{}

type Source interface {
	Name() string
	ProjectExists(ctx context.Context, imageName, imageTag string) (bool, error)
	GetVulnerabilities(ctx context.Context, imageName, imageTag string, includeSuppressed bool) ([]*Vulnerability, error)
	// TODO: add includeSuppressed bool
	GetVulnerabilitySummary(ctx context.Context, imageName, imageTag string) (*VulnerabilitySummary, error)
	MaintainSuppressedVulnerabilities(ctx context.Context, suppressed []*SuppressedVulnerability) error
	UploadAttestation(ctx context.Context, imageName string, imageTag string, att []byte) (uuid.UUID, error)
	Delete(ctx context.Context, imageName string, imageTag string) error
}

func New(config SourceConfig, log logrus.FieldLogger) (Source, error) {
	switch cfg := config.(type) {
	case DependencyTrackConfig:
		c, err := dependencytrack.NewClient(
			cfg.Url,
			cfg.Username,
			cfg.Password,
			log.WithField("subsystem", "dp-client"),
			// wrap the default transport with OpenTelemetry instrumentation
			dependencytrack.WithHTTPClient(&http.Client{Transport: otelhttp.NewTransport(http.DefaultTransport)}),
		)
		if err != nil {
			log.Fatalf("failed to create DependencyTrack client: %v", err)
		}

		return NewDependencytrackSource(c, log.WithField("source", "dependencytrack")), nil
	default:
		return nil, fmt.Errorf("unsupported source config type: %T", cfg)
	}
}

func SetupSources(configs []SourceConfig, log logrus.FieldLogger) ([]Source, error) {
	sources := make([]Source, 0)
	for _, config := range configs {
		s, err := New(config, log)
		if err != nil {
			return nil, err
		}
		sources = append(sources, s)
	}
	return sources, nil
}

type SourceId string

type Workload struct {
	Cluster   string
	Namespace string
	Name      string
	Type      string
	ImageName string
	ImageTag  string
}

type Severity string

func (s Severity) ToInt32() int32 {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	case SeverityUnassigned:
		return 4
	}
	return -1
}

const SeverityCritical = Severity("CRITICAL")
const SeverityHigh = Severity("HIGH")
const SeverityMedium = Severity("MEDIUM")
const SeverityLow = Severity("LOW")
const SeverityUnassigned = Severity("UNASSIGNED")

type Cve struct {
	Id          string
	Description string
	Title       string
	Link        string
	Severity    Severity
	References  map[string]string
}

type Vulnerability struct {
	Package       string
	Suppressed    bool
	Cve           *Cve
	LatestVersion string
	Metadata      VulnerabilityMetadata
}

type VulnerabilityMetadata interface {
	/*GetProjectId() string
	GetComponentId() string
	GetVulnerabilityId() string*/
}

type VulnerabilitySummary struct {
	Id         string
	Critical   int32
	High       int32
	Medium     int32
	Low        int32
	Unassigned int32
	RiskScore  int32
}

type SuppressedVulnerability struct {
	ImageName    string
	ImageTag     string
	CveId        string
	Package      string
	SuppressedBy string
	Reason       string
	State        string
	Suppressed   bool
	Metadata     VulnerabilityMetadata
}

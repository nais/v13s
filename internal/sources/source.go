package sources

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

type Source interface {
	Delete(ctx context.Context, imageName string, imageTag string) error
	GetVulnerabilities(ctx context.Context, imageName, imageTag string, includeSuppressed bool) ([]*Vulnerability, error)
	GetVulnerabilitySummary(ctx context.Context, imageName, imageTag string) (*VulnerabilitySummary, error)
	IsTaskInProgress(ctx context.Context, processToken string) (bool, error)
	MaintainSuppressedVulnerabilities(ctx context.Context, suppressed []*SuppressedVulnerability) error
	Name() string
	Identity() Identity
	ProjectExists(ctx context.Context, imageName, imageTag string) (bool, error)
	UploadAttestation(ctx context.Context, imageName string, imageTag string, att []byte) (*UploadAttestationResponse, error)
}

// Identity distinguishes concrete source instances of the same source type.
// For example, both dt-v4 and dt-v5 have type dependencytrack.
type Identity struct {
	Type     string
	Instance string
}

// Sources keeps the active source used by v13s separate from optional warmup
// sources. Active owns reads and state; warmup sources only receive SBOM work.
type Sources struct {
	active Source
	warmup []Source
}

func NewSet(active Source, warmup ...Source) (*Sources, error) {
	if active == nil {
		return nil, fmt.Errorf("active source must not be nil")
	}
	if active.Identity().Instance == "" {
		return nil, fmt.Errorf("active source instance must not be empty")
	}
	seen := map[string]struct{}{active.Identity().Instance: {}}
	for _, source := range warmup {
		if source == nil {
			return nil, fmt.Errorf("warmup source must not be nil")
		}
		instance := source.Identity().Instance
		if instance == "" {
			return nil, fmt.Errorf("warmup source instance must not be empty")
		}
		if _, exists := seen[instance]; exists {
			return nil, fmt.Errorf("duplicate source instance %q", instance)
		}
		seen[instance] = struct{}{}
	}
	return &Sources{active: active, warmup: warmup}, nil
}

func (s *Sources) Active() Source {
	return s.active
}

func (s *Sources) IsActive(instance string) bool {
	return s.active.Identity().Instance == instance
}

func (s *Sources) UploadInstances() []string {
	instances := make([]string, 0, len(s.warmup)+1)
	instances = append(instances, s.active.Identity().Instance)
	for _, source := range s.warmup {
		instances = append(instances, source.Identity().Instance)
	}
	return instances
}

func (s *Sources) Source(instance string) (Source, bool) {
	if s.active.Identity().Instance == instance {
		return s.active, true
	}
	for _, source := range s.warmup {
		if source.Identity().Instance == instance {
			return source, true
		}
	}
	return nil, false
}

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

const (
	SeverityCritical   = Severity("CRITICAL")
	SeverityHigh       = Severity("HIGH")
	SeverityMedium     = Severity("MEDIUM")
	SeverityLow        = Severity("LOW")
	SeverityUnassigned = Severity("UNASSIGNED")
)

type Cve struct {
	Id          string
	Description string
	Title       string
	Link        string
	Severity    Severity
	References  map[string]string
}

type Vulnerability struct {
	Package        string
	Suppressed     bool
	Cve            *Cve
	LatestVersion  string
	Metadata       VulnerabilityMetadata
	CvssScore      *float64
	EpssScore      *float64
	EpssPercentile *float64
}

type VulnerabilityMetadata any

type VulnerabilitySummary struct {
	Id         string
	Critical   int32
	High       int32
	Medium     int32
	Low        int32
	Unassigned int32
	ActNow     int32
	HighRisk   int32
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

type UploadAttestationResponse struct {
	AttestationId uuid.UUID
	ProcessToken  string
}

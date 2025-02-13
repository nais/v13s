package sources

import (
	"context"
	"github.com/nais/v13s/internal/dependencytrack"
)

type Source interface {
	Name() string
	SuppressVulnerability(ctx context.Context, vulnerability *Vulnerability) error
	GetSuppressedVulnerabilitiesForImage(ctx context.Context, image string) ([]*Vulnerability, error)
	GetVulnerabilites(ctx context.Context, id string, includeSuppressed bool) ([]*Vulnerability, error)
	GetVulnerabilitySummary(ctx context.Context, imageName, imageTag string) (*VulnerabilitySummary, error)
}

func NewDependencytrackSource(client dependencytrack.Client) Source {
	return &dependencytrackSource{client: client}
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
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityUnassigned:
		return 1
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

type Findings struct {
	WorkloadRef     *Workload
	Vulnerabilities []*Vulnerability
}

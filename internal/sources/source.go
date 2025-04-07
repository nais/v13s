package sources

import (
	"context"

	"github.com/google/uuid"
	"github.com/in-toto/in-toto-golang/in_toto"
)

type Source interface {
	Name() string
	SuppressVulnerability(ctx context.Context, suppressedVulnerability *SuppressedVulnerability) error
	GetVulnerabilities(ctx context.Context, imageName, imageTag string, includeSuppressed bool) ([]*Vulnerability, error)
	// TODO: add includeSuppressed bool
	GetVulnerabilitySummary(ctx context.Context, imageName, imageTag string) (*VulnerabilitySummary, error)
	MaintainSuppressedVulnerabilities(ctx context.Context, suppressed []*SuppressedVulnerability) error
	UploadSbom(ctx context.Context, workload *Workload, att *in_toto.CycloneDXStatement) (uuid.UUID, error)
	DeleteWorkload(ctx context.Context, ref uuid.UUID, workload *Workload) error
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

type Findings struct {
	WorkloadRef     *Workload
	Vulnerabilities []*Vulnerability
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

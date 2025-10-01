package source

import "github.com/google/uuid"

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

type UploadAttestationResponse struct {
	AttestationId uuid.UUID
	ProcessToken  string
}

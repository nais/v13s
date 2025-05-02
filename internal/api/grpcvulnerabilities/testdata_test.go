package grpcvulnerabilities_test

import (
	"fmt"

	"github.com/nais/v13s/internal/database/sql"
)

type Workload struct {
	Cluster      string
	Namespace    string
	Workload     string
	WorkloadType string
	ImageName    string
	ImageTag     string
	Vulnz        []*Vulnerability
	Summary      *sql.VulnerabilitySummary
}

type Vulnerability struct {
	vuln *sql.Vulnerability
	cve  *sql.Cve
}

func generateTestWorkloads(clusters, namespaces []string, workloadsPerNamespace, vulnsPerWorkload int) []*Workload {
	var workloads []*Workload

	// Iterate over clusters, namespaces, and workloads
	for _, cluster := range clusters {
		for _, namespace := range namespaces {
			for i := 1; i <= workloadsPerNamespace; i++ {
				imageName := fmt.Sprintf("image-%s-%s-workload-%d", cluster, namespace, i)
				imageTag := fmt.Sprintf("v%d.0", i)
				workload := &Workload{
					Cluster:      cluster,
					Namespace:    namespace,
					Workload:     fmt.Sprintf("workload-%d", i),
					WorkloadType: "app", // Could be randomized if needed
					ImageName:    imageName,
					ImageTag:     imageTag,
					Vulnz:        generateVulnerabilities(vulnsPerWorkload, i, imageName, imageTag), // Generate a different number of vulnerabilities
				}
				workload.Summary = &sql.VulnerabilitySummary{
					ImageName:  imageName,
					ImageTag:   imageTag,
					Critical:   0,
					High:       int32(vulnsPerWorkload),
					Medium:     0,
					Low:        0,
					Unassigned: 0,
					RiskScore:  0,
				}
				workloads = append(workloads, workload)
			}
		}
	}

	return workloads
}

// generateVulnerabilities creates a different number of vulnerabilities per workload
func generateVulnerabilities(numVulns, workloadIndex int, imageName string, imageTag string) []*Vulnerability {
	var vulns []*Vulnerability
	for j := 1; j <= numVulns; j++ {
		vulns = append(vulns, createVulnerability(fmt.Sprintf("CWE-%d-%d", workloadIndex, j), imageName, imageTag))
	}
	return vulns
}

// createVulnerability generates a predictable vulnerability instance
func createVulnerability(cveID string, imageName string, imageTag string) *Vulnerability {
	return &Vulnerability{
		vuln: &sql.Vulnerability{
			ImageName: imageName,
			ImageTag:  imageTag,
			Package:   fmt.Sprintf("package-%s", cveID),
			CveID:     cveID,
		},
		cve: &sql.Cve{
			CveID:    cveID,
			CveTitle: "CWE Title for " + cveID,
			CveDesc:  "Description for " + cveID,
			CveLink:  "https://example.com/" + cveID,
			Severity: 1,
		},
	}
}

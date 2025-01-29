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
}

type Vulnerability struct {
	vuln *sql.Vulnerability
	cwe  *sql.Cwe
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
func createVulnerability(cweID string, imageName string, imageTag string) *Vulnerability {

	return &Vulnerability{
		vuln: &sql.Vulnerability{
			ImageName: imageName,
			ImageTag:  imageTag,
			Package:   fmt.Sprintf("package-%s", cweID),
			CweID:     cweID,
		},
		cwe: &sql.Cwe{
			CweID:    cweID,
			CweTitle: "CWE Title for " + cweID,
			CweDesc:  "Description for " + cweID,
			CweLink:  "https://example.com/" + cweID,
			Severity: 1,
		},
	}
}

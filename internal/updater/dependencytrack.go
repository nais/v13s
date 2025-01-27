package updater

import (
	"context"
	"fmt"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/dependencytrack/client"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"
	"strings"
	"time"
)

func (u *Updater) getFilteredProjects(ctx context.Context, filter *vulnerabilities.Filter, limit int32, offset int32) ([]client.Project, error) {
	if filter == nil {
		return u.source.GetProjects(ctx, limit, offset)
	}

	if filter.Cluster != nil && filter.Namespace != nil {
		tagFilter := "team:" + *filter.Namespace
		return u.source.GetProjectsByTag(ctx, tagFilter, limit, offset)
	} else if filter.Cluster != nil {
		tagFilter := "env:" + *filter.Cluster
		return u.source.GetProjectsByTag(ctx, tagFilter, limit, offset)
	} else if filter.Namespace != nil {
		tagFilter := "team:" + *filter.Namespace
		return u.source.GetProjectsByTag(ctx, tagFilter, limit, offset)
	}

	// Fetch all projects if no specific cluster or namespace is defined
	return u.source.GetProjects(ctx, limit, offset)
}

func (u *Updater) getFindings(ctx context.Context, project client.Project, suppressed bool) ([]client.Finding, error) {
	projectFindings, err := u.source.GetFindings(ctx, project.Uuid, suppressed)
	if err != nil {
		return nil, err
	}
	return projectFindings, nil
}

func (u *Updater) getVulnerabilitiesForWorkload(ctx context.Context, project client.Project, workload *vulnerabilities.Workload, includeSuppressed bool) (*vulnerabilities.WorkloadVulnerabilities, error) {
	findings, err := u.getFindings(ctx, project, includeSuppressed)
	if err != nil {
		return nil, err
	}

	var vuln []*vulnerabilities.Vulnerability
	for _, finding := range findings {
		vulnerability, err := u.parseFindingToVulnerability(finding)
		if err != nil {
			return nil, err
		}
		vuln = append(vuln, vulnerability)
	}

	return &vulnerabilities.WorkloadVulnerabilities{
		Workload:        workload,
		Vulnerabilities: vuln,
		LastUpdated:     timestamppb.New(time.Now()),
	}, nil
}

func (u *Updater) processProjects(ctx context.Context, projects []client.Project, request *vulnerabilities.ListVulnerabilitiesRequest) ([]*vulnerabilities.WorkloadVulnerabilities, error) {
	var workloadVulnerabilities []*vulnerabilities.WorkloadVulnerabilities

	for _, project := range projects {
		workloads := u.extractWorkloadsFromProject(project)
		filteredWorkloads := u.filterWorkloads(workloads, request.Filter)

		for _, w := range filteredWorkloads {
			vuln, err := u.getVulnerabilitiesForWorkload(ctx, project, w, request.GetSuppressed())
			if err != nil {
				return nil, err
			}
			workloadVulnerabilities = append(workloadVulnerabilities, vuln)
		}
	}

	return workloadVulnerabilities, nil
}

func (u *Updater) parseFinding(imageName, imageTag string, finding client.Finding) (*sql.Vulnerability, *sql.Cwe, error) {
	component, componentOk := finding.GetComponentOk()
	if !componentOk {
		return nil, nil, fmt.Errorf("missing component for finding")
	}

	analysis, analysisOk := finding.GetAnalysisOk()
	if !analysisOk {
		return nil, nil, fmt.Errorf("missing analysis for finding")
	}

	vulnData, vulnOk := finding.GetVulnerabilityOk()
	if !vulnOk {
		return nil, nil, fmt.Errorf("missing vulnerability data for finding")
	}

	var severity vulnerabilities.Severity
	switch vulnData["severity"].(string) {
	case "CRITICAL":
		severity = vulnerabilities.Severity_CRITICAL
	case "HIGH":
		severity = vulnerabilities.Severity_HIGH
	case "MEDIUM":
		severity = vulnerabilities.Severity_MEDIUM
	case "LOW":
		severity = vulnerabilities.Severity_LOW
	default:
		severity = vulnerabilities.Severity_UNASSIGNED
	}

	var link string
	switch vulnData["source"].(string) {
	case "NVD":
		link = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", vulnData["vulnId"].(string))
	case "GITHUB":
		link = fmt.Sprintf("https://github.com/advisories/%s", vulnData["vulnId"].(string))
	}

	// TODO: Implement isSuppressed
	isSuppressed := analysis["isSuppressed"].(bool)
	fmt.Printf("isSuppressed: %v\n", isSuppressed)
	title := "unknown"
	desc := "unknown"
	if vulnData["title"] != nil {
		title = vulnData["title"].(string)
	}
	if vulnData["description"] != nil {
		desc = vulnData["description"].(string)
	}
	return &sql.Vulnerability{
			ImageName: imageName,
			ImageTag:  imageTag,
			Package:   component["purl"].(string),
			CweID:     vulnData["vulnId"].(string),
		}, &sql.Cwe{
			CweID:    vulnData["vulnId"].(string),
			CweTitle: title,
			CweDesc:  desc,
			CweLink:  link,
			Severity: int32(severity),
		},
		nil
}

func (u *Updater) parseFindingToVulnerability(finding client.Finding) (*vulnerabilities.Vulnerability, error) {
	component, componentOk := finding.GetComponentOk()
	if !componentOk {
		return nil, fmt.Errorf("missing component for finding")
	}

	analysis, analysisOk := finding.GetAnalysisOk()
	if !analysisOk {
		return nil, fmt.Errorf("missing analysis for finding")
	}

	vulnData, vulnOk := finding.GetVulnerabilityOk()
	if !vulnOk {
		return nil, fmt.Errorf("missing vulnerability data for finding")
	}

	var severity vulnerabilities.Severity
	switch vulnData["severity"].(string) {
	case "CRITICAL":
		severity = vulnerabilities.Severity_CRITICAL
	case "HIGH":
		severity = vulnerabilities.Severity_HIGH
	case "MEDIUM":
		severity = vulnerabilities.Severity_MEDIUM
	case "LOW":
		severity = vulnerabilities.Severity_LOW
	default:
		severity = vulnerabilities.Severity_UNASSIGNED
	}

	var link string
	switch vulnData["source"].(string) {
	case "NVD":
		link = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", vulnData["vulnId"].(string))
	case "GITHUB":
		link = fmt.Sprintf("https://github.com/advisories/%s", vulnData["vulnId"].(string))
	}

	isSuppressed := analysis["isSuppressed"].(bool)
	return &vulnerabilities.Vulnerability{
		Package: component["purl"].(string),
		Cwe: &vulnerabilities.Cwe{
			Id:          vulnData["vulnId"].(string),
			Title:       vulnData["title"].(string),
			Description: vulnData["description"].(string),
			Link:        link,
			Severity:    severity,
		},
		Suppressed: &isSuppressed,
	}, nil
}

func (u *Updater) extractWorkloadsFromProject(project client.Project) []*vulnerabilities.Workload {
	var workloads []*vulnerabilities.Workload

	for _, tag := range project.Tags {
		if tag.Name == nil || !strings.HasPrefix(*tag.Name, "workload:") {
			continue
		}

		parts := strings.Split(strings.TrimPrefix(*tag.Name, "workload:"), "|")
		if len(parts) != 4 {
			log.Printf("Invalid workload tag: %s", *tag.Name)
			continue
		}

		workloads = append(workloads, workload(parts[0], parts[1], parts[3], parts[2], *project.Name))
	}

	return workloads
}

func (u *Updater) filterWorkloads(workloads []*vulnerabilities.Workload, filter *vulnerabilities.Filter) []*vulnerabilities.Workload {
	if filter == nil || (filter.Workload == nil && filter.WorkloadType == nil) {
		return workloads
	}
	return collections.Filter(workloads, func(workload *vulnerabilities.Workload) bool {
		return matchesFilter(workload, filter)
	})
}

func matchesFilter(workload *vulnerabilities.Workload, filter *vulnerabilities.Filter) bool {
	if filter == nil {
		return true
	}
	if filter.Cluster != nil && workload.Cluster != *filter.Cluster {
		return false
	}
	if filter.Namespace != nil && workload.Namespace != *filter.Namespace {
		return false
	}
	if filter.Workload != nil && workload.Name != *filter.Workload {
		return false
	}
	if filter.WorkloadType != nil && workload.Type != *filter.WorkloadType {
		return false
	}
	return true
}

func workload(c, ns, n, t, i string) *vulnerabilities.Workload {
	return &vulnerabilities.Workload{
		Cluster:   c,
		Namespace: ns,
		Name:      n,
		Type:      t,
		Image:     i,
	}
}

package sources

import (
	"context"
	"fmt"
	"github.com/nais/v13s/internal/dependencytrack"
	"github.com/nais/v13s/internal/dependencytrack/client"
	"strings"
)

var ErrNoMetrics = fmt.Errorf("no metrics found")
var ErrNoProject = fmt.Errorf("no project found")

const DependencytrackSourceName = "dependencytrack"

type dependencytrackSource struct {
	client dependencytrack.Client
}

func (d *dependencytrackSource) Name() string {
	return DependencytrackSourceName
}

func (d *dependencytrackSource) GetVulnerabilitySummary(ctx context.Context, imageName, imageTag string) (*VulnerabilitySummary, error) {
	i := imageName
	t := imageTag
	if strings.Contains("nais-deploy-chicken", imageName) {
		i = "europe-north1-docker.pkg.dev/nais-io/nais/images/testapp"
		t = "latest"
	}

	p, err := d.client.GetProject(ctx, i, t)
	if err != nil {
		return nil, fmt.Errorf("getting project: %w", err)
	}

	if p == nil {
		return nil, ErrNoProject
	}

	if p.Metrics == nil {
		return nil, ErrNoMetrics
	}

	return &VulnerabilitySummary{
		Id:         p.Uuid,
		Critical:   p.Metrics.Critical,
		High:       p.Metrics.High,
		Medium:     p.Metrics.Medium,
		Low:        p.Metrics.Low,
		Unassigned: *p.Metrics.Unassigned,
		RiskScore:  int32(*p.Metrics.InheritedRiskScore),
	}, nil
}

func (d *dependencytrackSource) GetVulnerabilites(ctx context.Context, id string, includeSuppressed bool) ([]*Vulnerability, error) {
	findings, err := d.client.GetFindings(ctx, id, includeSuppressed)
	if err != nil {
		return nil, err
	}

	vulns := make([]*Vulnerability, 0)
	for _, f := range findings {
		v, err := parseFinding(f)
		if err != nil {
			return nil, err
		}
		vulns = append(vulns, v)
	}
	return vulns, nil
}

func parseFinding(finding client.Finding) (*Vulnerability, error) {
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

	var severity Severity
	switch vulnData["severity"].(string) {
	case "CRITICAL":
		severity = SeverityCritical
	case "HIGH":
		severity = SeverityHigh
	case "MEDIUM":
		severity = SeverityMedium
	case "LOW":
		severity = SeverityLow
	default:
		severity = SeverityUnassigned
	}

	var vulnId string
	if vulnData["vulnId"] != nil {
		vulnId = vulnData["vulnId"].(string)
	}

	var link string
	switch vulnData["source"].(string) {
	case "NVD":
		link = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", vulnId)
	case "GITHUB":
		link = fmt.Sprintf("https://github.com/advisories/%s", vulnId)
	case "UBUNTU":
		link = fmt.Sprintf("https://ubuntu.com/security/CVE-%s", vulnId)
	}

	suppressed := analysis["isSuppressed"].(bool)
	title := ""
	desc := "unknown"

	if vulnData["title"] != nil {
		title = vulnData["title"].(string)
		if title == "" && vulnData["cweName"] != nil {
			title = vulnData["cweName"].(string)
		}
	}

	if vulnData["description"] != nil {
		desc = vulnData["description"].(string)
	}

	purl := ""
	if component["purl"] != nil {
		purl = component["purl"].(string)
	}

	componentLatestVersion := ""
	if component["latestVersion"] != nil {
		componentLatestVersion = component["latestVersion"].(string)
	}

	references := map[string]string{}
	if vulnData["aliases"] != nil {
		aliases := vulnData["aliases"].([]interface{})
		for _, a := range aliases {
			alias := a.(map[string]interface{})
			if alias["cveId"] != nil && alias["ghsaId"] != nil {
				references[alias["cveId"].(string)] = alias["ghsaId"].(string)
			}
		}
	}

	return &Vulnerability{
		Package:       purl,
		Suppressed:    suppressed,
		LatestVersion: componentLatestVersion,
		Cve: &Cve{
			Id:          vulnId,
			Description: desc,
			Title:       title,
			Link:        link,
			Severity:    severity,
			References:  references,
		},
	}, nil
}

func (d *dependencytrackSource) SuppressVulnerability(ctx context.Context, vulnerability *Vulnerability) error {
	//TODO implement me
	panic("implement me")
}

func (d *dependencytrackSource) GetSuppressedVulnerabilitiesForImage(ctx context.Context, image string) ([]*Vulnerability, error) {
	//TODO implement me
	panic("implement me")
}

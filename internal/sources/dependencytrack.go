package sources

import (
	"context"
	"fmt"
	"github.com/nais/v13s/internal/sources/dependencytrack"
	"github.com/nais/v13s/internal/sources/dependencytrack/client"
	"github.com/sirupsen/logrus"
	"strings"
)

var ErrNoMetrics = fmt.Errorf("no metrics found")
var ErrNoProject = fmt.Errorf("no project found")

const DependencytrackSourceName = "dependencytrack"

type dependencytrackSource struct {
	client dependencytrack.Client
	log    *logrus.Entry
}

var _ Source = &dependencytrackSource{}

type VulnerabilityMatch struct {
	Finding  client.Finding
	VulnId   string
	VulnUuid string
	Found    bool
}

// TODO: add a cache? maybe for projects only?
func NewDependencytrackSource(client dependencytrack.Client, log *logrus.Entry) Source {
	return &dependencytrackSource{
		client: client,
		log:    log,
	}
}

func (d *dependencytrackSource) Name() string {
	return DependencytrackSourceName
}

func (d *dependencytrackSource) GetVulnerabilities(ctx context.Context, imageName, imageTag string, includeSuppressed bool) ([]*Vulnerability, error) {
	p, err := d.client.GetProject(ctx, imageName, imageTag)
	if err != nil {
		return nil, fmt.Errorf("getting project: %w", err)
	}

	if p == nil {
		return nil, ErrNoProject
	}

	findings, err := d.client.GetFindings(ctx, *p.Uuid, "", includeSuppressed)
	if err != nil {
		return nil, fmt.Errorf("getting findings for project %s: %w", *p.Uuid, err)
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

func (d *dependencytrackSource) MaintainSuppressedVulnerabilities(ctx context.Context, suppressed []*SuppressedVulnerability) error {
	d.log.Debug("maintaining suppressed vulnerabilities")
	projectId := ""
	for _, v := range suppressed {
		var metadata *dependencytrackVulnMetadata
		if m, ok := v.Metadata.(*dependencytrackVulnMetadata); ok {
			metadata = m
		}
		if metadata == nil {
			d.log.Warnf("missing metadata for suppressed vulnerability, CveId '%s', Package '%s'", v.CveId, v.Package)
			continue
		}

		projectId = metadata.projectId

		an, err := d.client.GetAnalysisTrailForImage(ctx, metadata.projectId, metadata.componentId, metadata.vulnerabilityUuid)
		if err != nil {
			return err
		}
		d.log.Debug("analysis trail for vulnerability found")

		if an == nil {
			d.log.Warnf("no analysis trail found for vulnerability %s in project %s", v.CveId, metadata.projectId)
			return nil
		}

		if *an.IsSuppressed == v.Suppressed {
			d.log.Infof("vulnerability %s suppression status is correct in project %s", v.CveId, metadata.projectId)
			continue
		}

		if an.AnalysisState == v.State {
			d.log.Infof("vulnerability %s state is correct in project %s", v.CveId, metadata.projectId)
			continue
		}

		if err := d.client.UpdateFinding(
			ctx,
			v.SuppressedBy,
			v.Reason,
			metadata.projectId,
			metadata.componentId,
			metadata.vulnerabilityUuid,
			v.State,
			v.Suppressed,
		); err != nil {
			return fmt.Errorf("suppressing vulnerability %s in project %s: %w", v.CveId, metadata.projectId, err)
		}
	}

	if projectId != "" {
		err := d.client.TriggerAnalysis(ctx, projectId)
		if err != nil {
			return fmt.Errorf("triggering analysis for project %s: %w", projectId, err)
		}
	}

	d.log.Debug("suppressed vulnerabilities maintained")

	return nil
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
	d.log.Debug("got project", t)

	if p == nil {
		return nil, ErrNoProject
	}

	if p.Metrics == nil {
		return nil, ErrNoMetrics
	}

	return &VulnerabilitySummary{
		Id:         *p.Uuid,
		Critical:   p.Metrics.Critical,
		High:       p.Metrics.High,
		Medium:     p.Metrics.Medium,
		Low:        p.Metrics.Low,
		Unassigned: *p.Metrics.Unassigned,
		RiskScore:  int32(*p.Metrics.InheritedRiskScore),
	}, nil
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
	if severityStr, ok := vulnData["severity"].(string); ok {
		switch severityStr {
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
	} else {
		// default to unassigned if severity is missing or it is not a known value
		severity = SeverityUnassigned
	}

	var vulnId string
	if v, ok := vulnData["vulnId"].(string); ok {
		vulnId = v
	}

	var projectId string
	if p, ok := component["project"].(string); ok {
		projectId = p
	}
	var componentId string
	if c, ok := component["uuid"].(string); ok {
		componentId = c
	}
	var vulnerabilityUuid string
	if v, ok := vulnData["uuid"].(string); ok {
		vulnerabilityUuid = v
	}

	var link string
	if source, ok := vulnData["source"].(string); ok {
		switch source {
		case "NVD":
			link = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", vulnId)
		case "GITHUB":
			link = fmt.Sprintf("https://github.com/advisories/%s", vulnId)
		case "UBUNTU":
			link = fmt.Sprintf("https://ubuntu.com/security/CVE-%s", vulnId)
		case "OSSINDEX":
			link = fmt.Sprintf("https://ossindex.sonatype.org/vuln/%s", vulnId)
		}
	}

	suppressed := false
	if s, ok := analysis["isSuppressed"].(bool); ok {
		suppressed = s
	}

	title := ""
	if t, ok := vulnData["title"].(string); ok && t != "" {
		title = t
	} else if cwe, ok := vulnData["cweName"].(string); ok {
		title = cwe
	}

	desc := "unknown"
	if d, ok := vulnData["description"].(string); ok {
		desc = d
	}

	purl := ""
	if p, ok := component["purl"].(string); ok {
		purl = p
	}

	componentLatestVersion := ""
	if lv, ok := component["latestVersion"].(string); ok {
		componentLatestVersion = lv
	}

	references := map[string]string{}
	if aliases, ok := vulnData["aliases"].([]interface{}); ok {
		for _, a := range aliases {
			if alias, ok := a.(map[string]interface{}); ok {
				if cveId, ok := alias["cveId"].(string); ok {
					if ghsaId, ok := alias["ghsaId"].(string); ok {
						references[cveId] = ghsaId
					}
				}
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
		Metadata: &dependencytrackVulnMetadata{
			projectId:         projectId,
			componentId:       componentId,
			vulnerabilityUuid: vulnerabilityUuid,
		},
	}, nil
}

type dependencytrackVulnMetadata struct {
	projectId         string
	componentId       string
	vulnerabilityUuid string
}

func (d *dependencytrackSource) SuppressVulnerability(ctx context.Context, v *SuppressedVulnerability) error {
	projects, err := d.getProjectsForImage(ctx, v.ImageName)
	if err != nil {
		return err
	}

	anyUpdateMade := false
	for _, p := range projects {
		updateMade, err := d.processProject(ctx, p, v)
		if err != nil {
			return err
		}
		if updateMade {
			anyUpdateMade = true
		}
	}

	if !anyUpdateMade {
		d.log.Debugf("no updates made for vulnerability %s across any project", v.CveId)
	}

	return nil
}

func (d *dependencytrackSource) getProjectsForImage(ctx context.Context, imageName string) ([]client.Project, error) {
	projects, err := d.client.GetProjectsByTag(ctx, fmt.Sprintf("project:%s", imageName), 10, 0)
	if err != nil {
		return nil, fmt.Errorf("getting projects: %w", err)
	}
	return projects, nil
}

func (d *dependencytrackSource) processProject(ctx context.Context, p client.Project, v *SuppressedVulnerability) (bool, error) {
	findings, err := d.client.GetFindings(ctx, *p.Uuid, v.CveId, true)
	if err != nil {
		return false, fmt.Errorf("getting findings for project %s: %w", *p.Uuid, err)
	}

	match, err := d.findMatchingVulnerability(findings, v.CveId)
	if err != nil {
		return false, err
	}

	if !match.Found {
		d.log.Warnf("vulnerability %s not found in project %s", v.CveId, *p.Uuid)
		return false, nil
	}

	componentId, err := d.getComponentId(match.Finding)
	if err != nil {
		return false, err
	}

	an, err := d.client.GetAnalysisTrailForImage(ctx, *p.Uuid, componentId, match.VulnUuid)
	if err != nil {
		return false, err
	}

	if an == nil {
		d.log.Warnf("no analysis trail found for vulnerability %s in project %s", v.CveId, *p.Uuid)
		return false, nil
	}

	needsUpdate := d.checkAndLogUpdates(an, v, *p.Uuid)
	if !needsUpdate {
		d.log.Infof("no update needed for vulnerability %s in project %s", v.CveId, *p.Uuid)
		return false, nil
	}

	if err := d.client.UpdateFinding(ctx, v.SuppressedBy, v.Reason, *p.Uuid, componentId, match.VulnUuid, v.State, v.Suppressed); err != nil {
		return false, fmt.Errorf("suppressing vulnerability %s in project %s: %w", v.CveId, *p.Uuid, err)
	}

	return true, nil
}

func (d *dependencytrackSource) findMatchingVulnerability(findings []client.Finding, cveId string) (VulnerabilityMatch, error) {
	var match VulnerabilityMatch

	for _, f := range findings {
		vulnData, vulnOk := f.GetVulnerabilityOk()
		if vulnOk {
			if vv, ok := vulnData["vulnId"].(string); ok {
				match.VulnId = vv
			}
			if vu, ok := vulnData["uuid"].(string); ok {
				match.VulnUuid = vu
			}
			if match.VulnId == cveId {
				match.Finding = f
				match.Found = true
				return match, nil
			}
		}
	}

	return match, nil
}

func (d *dependencytrackSource) getComponentId(finding client.Finding) (string, error) {
	component, componentOk := finding.GetComponentOk()
	if !componentOk {
		return "", fmt.Errorf("missing component data for finding")
	}

	componentId, componentIdOk := component["uuid"].(string)
	if !componentIdOk {
		return "", fmt.Errorf("missing component id for finding")
	}
	return componentId, nil
}

func (d *dependencytrackSource) checkAndLogUpdates(an *client.Analysis, v *SuppressedVulnerability, projectId string) bool {
	needsUpdate := false
	if *an.IsSuppressed != v.Suppressed {
		d.log.Infof("vulnerability %s suppression status changed from %t to %t in project %s", v.CveId, *an.IsSuppressed, v.Suppressed, projectId)
		needsUpdate = true
	}

	if an.AnalysisState != v.State {
		d.log.Infof("vulnerability %s state changed from %s to %s in project %s", v.CveId, an.AnalysisState, v.State, projectId)
		needsUpdate = true
	}

	return needsUpdate
}

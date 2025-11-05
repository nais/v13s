package sources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/nais/dependencytrack/pkg/dependencytrack"
	"github.com/nais/v13s/internal/model"
	"github.com/sirupsen/logrus"
)

var ErrNoMetrics = fmt.Errorf("no metrics found")
var ErrNoProject = fmt.Errorf("no project found")

const DependencytrackSourceName = "dependencytrack"

type dependencytrackSource struct {
	client dependencytrack.Client
	log    *logrus.Entry
}

var _ Source = &dependencytrackSource{}

func NewDependencytrackSource(client dependencytrack.Client, log *logrus.Entry) Source {
	return &dependencytrackSource{
		client: client,
		log:    log,
	}
}

func (d *dependencytrackSource) Name() string {
	return DependencytrackSourceName
}

func (d *dependencytrackSource) IsTaskInProgress(ctx context.Context, tokenProcess string) (bool, error) {
	_, err := uuid.Parse(tokenProcess)
	if err != nil {
		return false, fmt.Errorf("parsing token process UUID: %w", err)
	}
	return d.client.IsTaskInProgress(ctx, tokenProcess)
}

func (d *dependencytrackSource) UploadAttestation(ctx context.Context, imageName string, imageTag string, sbom []byte) (*UploadAttestationResponse, error) {
	d.log.Debugf("uploading sbom for workload %v", imageName)

	res, err := d.client.CreateProjectWithSbom(ctx, imageName, imageTag, sbom)
	if err != nil {
		if errors.As(err, &dependencytrack.ClientError{}) {
			return nil, model.ToUnrecoverableError(err, "dependencytrack")
		}
		if errors.As(err, &dependencytrack.ServerError{}) {
			return nil, model.ToRecoverableError(err, "dependencytrack")
		}
		return nil, fmt.Errorf("creating project with sbom: %w", err)
	}

	id, err := uuid.Parse(res.Uuid)
	if err != nil {
		return nil, fmt.Errorf("parsing project id: %w", err)
	}
	return &UploadAttestationResponse{
		AttestationId: id,
		ProcessToken:  res.Token,
	}, nil
}

func (d *dependencytrackSource) Delete(ctx context.Context, imageName string, imageTag string) error {
	p, err := d.client.GetProject(ctx, imageName, imageTag)
	if err != nil {
		return fmt.Errorf("getting project: %w", err)
	}
	if p == nil {
		d.log.Debugf("no project found for image %s:%s", imageName, imageTag)
		return nil
	}

	err = d.client.DeleteProject(ctx, p.Uuid)
	if err != nil {
		return fmt.Errorf("deleting project: %w", err)
	}

	d.log.Debugf("deleted project %s:%s", imageName, imageTag)
	return nil
}

func (d *dependencytrackSource) ProjectExists(ctx context.Context, imageName, imageTag string) (bool, error) {
	d.log.Debugf("getting project for image %s:%s", imageName, imageTag)
	p, err := d.client.GetProject(ctx, imageName, imageTag)
	if err != nil {
		return false, fmt.Errorf("getting project: %w", err)
	}

	if p == nil {
		d.log.Debugf("no project found for image %s:%s", imageName, imageTag)
		return false, nil
	}

	return true, nil
}

func (d *dependencytrackSource) GetVulnerabilities(ctx context.Context, imageName, imageTag string, includeSuppressed bool) ([]*Vulnerability, error) {
	p, err := d.client.GetProject(ctx, imageName, imageTag)
	if err != nil {
		return nil, fmt.Errorf("getting project: %w", err)
	}

	if p == nil {
		return nil, ErrNoProject
	}

	vulns, err := d.client.GetFindings(ctx, p.Uuid, includeSuppressed)
	if err != nil {
		return nil, fmt.Errorf("getting findings for project %s: %w", p.Uuid, err)
	}

	vv := make([]*Vulnerability, 0, len(vulns))
	for _, v := range vulns {
		var m *dependencytrack.VulnMetadata
		if v.Metadata != nil {
			m = &dependencytrack.VulnMetadata{
				ProjectId:         v.Metadata.ProjectId,
				ComponentId:       v.Metadata.ComponentId,
				VulnerabilityUuid: v.Metadata.VulnerabilityUuid,
			}
		} else {
			d.log.Warnf("missing metadata for vulnerability, CveId '%s', Package '%s'", v.Cve.Id, v.Package)
		}
		vv = append(vv, &Vulnerability{
			Cve: &Cve{
				Id:          v.Cve.Id,
				Description: v.Cve.Description,
				Title:       v.Cve.Title,
				Link:        v.Cve.Link,
				Severity:    Severity(v.Cve.Severity),
				References:  v.Cve.References,
			},
			Package:       v.Package,
			Suppressed:    v.Suppressed,
			LatestVersion: v.LatestVersion,
			Metadata:      m,
		})
	}

	return vv, nil
}

func (d *dependencytrackSource) MaintainSuppressedVulnerabilities(ctx context.Context, suppressed []*SuppressedVulnerability) error {
	// get projects and update findings
	d.log.Debug("maintaining suppressed vulnerabilities")
	triggeredProjects := make(map[string]struct{})

	for _, v := range suppressed {
		metadata, ok := v.Metadata.(*dependencytrack.VulnMetadata)
		if !ok || metadata == nil {
			d.log.Warnf("missing metadata for suppressed vulnerability, CveId '%s', Package '%s'", v.CveId, v.Package)
			continue
		}

		an, err := d.client.GetAnalysisTrailForImage(ctx, metadata.ProjectId, metadata.ComponentId, metadata.VulnerabilityUuid)
		if err != nil {
			return err
		}

		if d.shouldUpdateFinding(an, v) {
			d.log.Debug("analysis trail for vulnerability found")
			if err := d.updateFinding(ctx, metadata, v); err != nil {
				return err
			}
			triggeredProjects[metadata.ProjectId] = struct{}{}
		} else {
			d.log.Infof("vulnerability %s is already up to date in project %s", v.CveId, metadata.ProjectId)
		}
	}

	// TODO: postgres river: trigger analysis for projects with updated findings
	for projectID := range triggeredProjects {
		if err := d.client.TriggerAnalysis(ctx, projectID); err != nil {
			return fmt.Errorf("triggering analysis for project %s: %w", projectID, err)
		}
	}

	d.log.Debug("suppressed vulnerabilities maintained")
	return nil
}

func (d *dependencytrackSource) GetVulnerabilitySummary(ctx context.Context, imageName, imageTag string) (*VulnerabilitySummary, error) {
	i := imageName
	t := imageTag
	// TODO: remove this hack when we have a better way to handle test images
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
		Id:         p.Uuid,
		Critical:   p.Metrics.Critical,
		High:       p.Metrics.High,
		Medium:     p.Metrics.Medium,
		Low:        p.Metrics.Low,
		Unassigned: p.Metrics.Unassigned,
		RiskScore:  int32(p.Metrics.InheritedRiskScore),
	}, nil
}

func (d *dependencytrackSource) shouldUpdateFinding(an *dependencytrack.Analysis, v *SuppressedVulnerability) bool {
	if an == nil {
		return true
	}
	if an.IsSuppressed != nil && *an.IsSuppressed != v.Suppressed {
		return true
	}
	return an.AnalysisState != v.State
}

func (d *dependencytrackSource) updateFinding(ctx context.Context, metadata *dependencytrack.VulnMetadata, v *SuppressedVulnerability) error {
	vReq := dependencytrack.AnalysisRequest{
		SuppressedBy:    v.SuppressedBy,
		Reason:          v.Reason,
		ProjectId:       metadata.ProjectId,
		ComponentId:     metadata.ComponentId,
		VulnerabilityId: metadata.VulnerabilityUuid,
		State:           v.State,
		Suppressed:      v.Suppressed,
	}
	err := d.client.UpdateFinding(ctx, vReq)
	if err != nil {
		return fmt.Errorf("suppressing vulnerability %s in project %s: %w", v.CveId, metadata.ProjectId, err)
	}
	return nil
}

package dependencytrack

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sirupsen/logrus"

	"github.com/nais/v13s/internal/sources/dependencytrack/auth"
	"github.com/nais/v13s/internal/sources/dependencytrack/client"
)

var _ Client = &dependencyTrackClient{}

type Client interface {
	GetFindings(ctx context.Context, uuid, vulnerabilityId string, suppressed bool) ([]client.Finding, error)
	GetProjectsByTag(ctx context.Context, tag string, limit, offset int32) ([]client.Project, error)
	GetProject(ctx context.Context, name, version string) (*client.Project, error)
	GetProjects(ctx context.Context, limit, offset int32) ([]client.Project, error)
	UpdateFinding(ctx context.Context, suppressedBy, reason, projectId, componentId, vulnerabilityId, state string, suppressed bool) error
	GetAnalysisTrailForImage(ctx context.Context, projectId, componentId, vulnerabilityId string) (*client.Analysis, error)
	TriggerAnalysis(ctx context.Context, uuid string) error
	CreateProject(ctx context.Context, name, version string, tags []string) (*client.Project, error)
	UploadSbom(ctx context.Context, projectId string, sbom *in_toto.CycloneDXStatement) error
	CreateProjectWithSbom(ctx context.Context, imageName, imageTag string, sbom *in_toto.CycloneDXStatement, workloadRef *WorkloadRef) error
}

type dependencyTrackClient struct {
	client *client.APIClient
	auth   auth.Auth
	log    *logrus.Entry
}

type WorkloadRef struct {
	Cluster   string
	Namespace string
	Type      string
	Name      string
}

func NewClient(url string, team auth.Team, username auth.Username, password auth.Password, log *logrus.Entry) (Client, error) {
	if url == "" {
		return nil, fmt.Errorf("NewClient: URL cannot be empty")
	}

	clientConfig := setupConfig(url)
	apiClient := client.NewAPIClient(clientConfig)
	userPasSource := auth.NewUsernamePasswordSource(username, password, apiClient, log)
	return &dependencyTrackClient{
		client: apiClient,
		auth:   auth.NewApiKeySource(team, userPasSource, apiClient, log),
		log:    log,
	}, nil
}

func setupConfig(rawURL string) *client.Configuration {
	cfg := client.NewConfiguration()
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		cfg.Scheme = "https"
	} else {
		cfg.Scheme = parsedURL.Scheme
		if cfg.Scheme == "" {
			cfg.Scheme = "https"
		}
	}

	cfg.Servers = client.ServerConfigurations{{URL: rawURL}}
	return cfg
}

func (c *dependencyTrackClient) CreateProjectWithSbom(ctx context.Context, imageName, imageTag string, sbom *in_toto.CycloneDXStatement, workloadRef *WorkloadRef) error {
	tags := []string{
		fmt.Sprintf("cluster:%s", workloadRef.Cluster),
		fmt.Sprintf("namespace:%s", workloadRef.Namespace),
		fmt.Sprintf("workload:%s", workloadRef.Cluster+"|"+workloadRef.Namespace+"|"+workloadRef.Type+"|"+workloadRef.Name),
		fmt.Sprintf("image:%s", imageName+":"+imageTag),
	}

	p, err := c.CreateProject(ctx, imageName, imageTag, tags)
	if err != nil {
		if !strings.Contains(err.Error(), "project already exists") {
			c.log.Errorf("create project: %v", err)
			return err
		}
	}

	if p == nil {
		p, err = c.GetProject(ctx, imageName, imageTag)
		if err != nil {
			return fmt.Errorf("failed to get project: %w", err)
		}
	}

	if err = c.UploadSbom(ctx, *p.Uuid, sbom); err != nil {
		return err
	}

	if err = c.TriggerAnalysis(ctx, *p.Uuid); err != nil {
		c.log.Warnf("trigger analysis: %v", err)
	}
	return nil
}

func (c *dependencyTrackClient) CreateProject(ctx context.Context, name, version string, tags []string) (*client.Project, error) {
	return withAuthContextValue(c, ctx, func(apiKeyCtx context.Context) (*client.Project, error) {
		active := true
		classifier := "APPLICATION"
		t := make([]client.Tag, 0)
		for _, tag := range tags {
			t = append(t, client.Tag{
				Name: &tag,
			})
		}
		req := c.client.ProjectAPI.CreateProject(apiKeyCtx).Body(client.Project{
			Name:       &name,
			Active:     &active,
			Classifier: &classifier,
			Version:    &version,
			Tags:       t,
			Parent:     nil,
		})

		project, resp, err := req.Execute()
		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusConflict {
				return nil, fmt.Errorf("project already exists")
			}
			return nil, fmt.Errorf("failed to create project: %w, details: %s", err, parseErrorResponseBody(resp))
		}

		return project, nil
	})
}

func (c *dependencyTrackClient) UploadSbom(ctx context.Context, projectId string, sbom *in_toto.CycloneDXStatement) error {
	b, err := json.Marshal(sbom.Predicate)
	if err != nil {
		return fmt.Errorf("failed to marshal sbom: %w", err)
	}

	return c.withAuthContext(ctx, func(apiKeyCtx context.Context) error {
		req := c.client.BomAPI.UploadBom(apiKeyCtx).Bom(string(b)).Project(projectId).AutoCreate(false)
		_, resp, err := req.Execute()
		if err != nil {
			return fmt.Errorf("failed to upload sbom: %w details: %s", err, parseErrorResponseBody(resp))
		}
		return nil
	})
}

// Is this function lacking pagination for all findings in a project or do we not need it?
// https://github.com/DependencyTrack/dependency-track/issues/3811
// https://github.com/DependencyTrack/dependency-track/issues/4677
func (c *dependencyTrackClient) GetFindings(ctx context.Context, uuid, vulnId string, suppressed bool) ([]client.Finding, error) {
	return withAuthContextValue(c, ctx, func(apiKeyCtx context.Context) ([]client.Finding, error) {
		req := c.client.FindingAPI.GetFindingsByProject(apiKeyCtx, uuid).Suppressed(suppressed)

		switch {
		case strings.Contains(vulnId, "CVE-"):
			req.Source("NVD")
		case strings.Contains(vulnId, "GHSA-"):
			req.Source("GITHUB")
		case strings.Contains(vulnId, "TRIVY-"):
			req.Source("TRIVY")
		case strings.Contains(vulnId, "NPM-"):
			req.Source("NPM")
		case strings.Contains(vulnId, "UBUNTU-"):
			req.Source("UBUNTU")
		case strings.Contains(vulnId, "OSSINDEX-"):
			req.Source("OSSINDEX")
		}

		findings, resp, err := req.Execute()
		if err != nil {
			return nil, fmt.Errorf("failed to get findings for project %s: %w, details: %s", uuid, err, parseErrorResponseBody(resp))
		}

		return findings, nil
	})
}

func (c *dependencyTrackClient) paginateProjects(ctx context.Context, limit, offset int32, callFunc func(ctx context.Context, offset int32) ([]client.Project, error)) ([]client.Project, error) {
	var allProjects []client.Project

	for {
		projects, err := callFunc(ctx, offset)
		if err != nil {
			return nil, err
		}

		allProjects = append(allProjects, projects...)

		if len(projects) < int(limit) {
			break
		}

		offset += limit
	}

	return allProjects, nil
}

func (c *dependencyTrackClient) GetProjectsByTag(ctx context.Context, tag string, limit, offset int32) ([]client.Project, error) {
	return withAuthContextValue(c, ctx, func(apiKeyCtx context.Context) ([]client.Project, error) {
		return c.paginateProjects(apiKeyCtx, limit, offset, func(ctx context.Context, offset int32) ([]client.Project, error) {
			pageNumber := (offset / limit) + 1
			projects, resp, err := c.client.ProjectAPI.GetProjectsByTag(ctx, tag).
				PageSize(limit).
				PageNumber(pageNumber).
				Execute()

			if err != nil {
				return nil, fmt.Errorf("failed to get projects by tag: %w details: %s", err, parseErrorResponseBody(resp))
			}

			return projects, err
		})
	})
}

func (c *dependencyTrackClient) GetProject(ctx context.Context, name, version string) (*client.Project, error) {
	return withAuthContextValue(c, ctx, func(apiKeyCtx context.Context) (*client.Project, error) {
		project, resp, err := c.client.ProjectAPI.GetProjectByNameAndVersion(apiKeyCtx).
			Name(name).
			Version(version).
			Execute()

		if err != nil && resp != nil && resp.StatusCode == 404 {
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				return nil, fmt.Errorf("failed to read response body: %w", readErr)
			}

			if strings.Contains(string(body), "The project could not be found") {
				return nil, nil
			}

			return nil, fmt.Errorf("project not found: %s", string(body))
		}

		return project, err
	})
}

func (c *dependencyTrackClient) GetProjects(ctx context.Context, limit, offset int32) ([]client.Project, error) {
	return withAuthContextValue(c, ctx, func(apiKeyCtx context.Context) ([]client.Project, error) {
		return c.paginateProjects(apiKeyCtx, limit, offset, func(ctx context.Context, offset int32) ([]client.Project, error) {
			pageNumber := (offset / limit) + 1
			projects, resp, err := c.client.ProjectAPI.GetProjects(ctx).
				PageSize(limit).
				PageNumber(pageNumber).
				Execute()
			return projects, fmt.Errorf("failed to get projects: %w details: %s", err, parseErrorResponseBody(resp))
		})
	})
}

func (c *dependencyTrackClient) UpdateFinding(
	ctx context.Context,
	suppressedBy, reason string,
	projectId, componentId, vulnerabilityId, state string,
	suppressed bool,
) error {
	return c.withAuthContext(ctx, func(apiKeyCtx context.Context) error {
		comment := fmt.Sprintf("on-behalf-of:%s|suppressed:%t|state:%s|comment:%s", suppressedBy, suppressed, state, reason)
		analysisJustification := "NOT_SET"
		analysisResponse := "NOT_SET"
		analysisRequest := client.AnalysisRequest{
			Vulnerability:         vulnerabilityId,
			Component:             componentId,
			Project:               &projectId,
			AnalysisState:         &state,
			AnalysisJustification: &analysisJustification,
			AnalysisResponse:      &analysisResponse,
			AnalysisDetails:       &reason,
			Comment:               &comment,
			Suppressed:            &suppressed,
		}

		_, resp, err := c.client.AnalysisAPI.UpdateAnalysis(apiKeyCtx).
			Body(analysisRequest).
			Execute()

		if err != nil {
			return fmt.Errorf("failed to update finding: %v details: %s", err, parseErrorResponseBody(resp))
		}

		return nil
	})
}

func (c *dependencyTrackClient) TriggerAnalysis(ctx context.Context, uuid string) error {
	// Fire and forget
	return c.withAuthContext(ctx, func(apiKeyCtx context.Context) error {
		_, _, err := c.client.FindingAPI.AnalyzeProject(apiKeyCtx, uuid).Execute()
		if err != nil {
			return fmt.Errorf("failed to trigger analysis: %w", err)
		}
		return nil
	})
}

func (c *dependencyTrackClient) GetAnalysisTrailForImage(
	ctx context.Context,
	projectId, componentID, vulnerabilityId string,
) (*client.Analysis, error) {
	return withAuthContextValue(c, ctx, func(apiKeyCtx context.Context) (*client.Analysis, error) {
		trail, resp, err := c.client.AnalysisAPI.RetrieveAnalysis(apiKeyCtx).
			Project(projectId).
			Component(componentID).
			Vulnerability(vulnerabilityId).
			Execute()

		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				return nil, nil
			}
			return nil, fmt.Errorf("failed to get analysis trail: %w details %s", err, parseErrorResponseBody(resp))
		}
		return trail, nil
	})
}

func parseErrorResponseBody(resp *http.Response) string {
	if resp == nil || resp.Body == nil {
		return "no response body"
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Sprintf("failed to read response body: %v", err)
	}

	return string(body)
}

func (c *dependencyTrackClient) withAuthContext(ctx context.Context, fn func(ctx context.Context) error) error {
	apiKeyCtx, err := c.auth.ContextHeaders(ctx)
	if err != nil {
		return fmt.Errorf("auth error: %w", err)
	}
	return fn(apiKeyCtx)
}

func withAuthContextValue[T any](c *dependencyTrackClient, ctx context.Context, fn func(ctx context.Context) (T, error)) (T, error) {
	apiKeyCtx, err := c.auth.ContextHeaders(ctx)
	if err != nil {
		var zero T
		return zero, fmt.Errorf("auth error: %w", err)
	}
	return fn(apiKeyCtx)
}

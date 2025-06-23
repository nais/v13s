package dependencytrack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/nais/v13s/internal/sources/dependencytrack/auth"
	"github.com/nais/v13s/internal/sources/dependencytrack/client"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

var _ Client = &dependencyTrackClient{}

var projectLocks sync.Map
var projects = cache.New(5*time.Minute, 10*time.Minute)

type Client interface {
	GetFindings(ctx context.Context, uuid, vulnerabilityId string, suppressed bool) ([]client.Finding, error)
	GetProjectsByTag(ctx context.Context, tag string, limit, offset int32) ([]client.Project, error)
	GetProject(ctx context.Context, name, version string) (*client.Project, error)
	GetProjects(ctx context.Context, limit, offset int32) ([]client.Project, error)
	UpdateFinding(ctx context.Context, suppressedBy, reason, projectId, componentId, vulnerabilityId, state string, suppressed bool) error
	GetAnalysisTrailForImage(ctx context.Context, projectId, componentId, vulnerabilityId string) (*client.Analysis, error)
	TriggerAnalysis(ctx context.Context, uuid string) error
	CreateProject(ctx context.Context, name, version string, tags []client.Tag) (*client.Project, error)
	UploadSbom(ctx context.Context, projectId string, sbom *in_toto.CycloneDXStatement) error
	CreateOrUpdateProjectWithSbom(ctx context.Context, sbom *in_toto.CycloneDXStatement, workloadRef *WorkloadRef) (string, error)
	CreateProjectWithSbom(ctx context.Context, sbom *in_toto.CycloneDXStatement, imageName, imageTag string) (string, error)
	DeleteProject(ctx context.Context, uuid string) error
	UpdateProject(ctx context.Context, project *client.Project) (*client.Project, error)
}

type ClientError struct {
	error
}

type ServerError struct {
	error
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
	ImageName string
	ImageTag  string
}

func NewClient(url string, team auth.Team, username auth.Username, password auth.Password, pool *pgxpool.Pool, log *logrus.Entry) (Client, error) {
	if url == "" {
		return nil, fmt.Errorf("NewClient: URL cannot be empty")
	}

	clientConfig := setupConfig(url)
	apiClient := client.NewAPIClient(clientConfig)
	userPasSource := auth.NewUsernamePasswordSource(username, password, apiClient, log)
	return &dependencyTrackClient{
		client: apiClient,
		auth:   auth.NewApiKeySource(team, userPasSource, apiClient, pool, log),
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
	// wrap the default transport with OpenTelemetry instrumentation
	cfg.HTTPClient = &http.Client{
		Transport: otelhttp.NewTransport(http.DefaultTransport),
	}

	return cfg
}

func (c *dependencyTrackClient) CreateProjectWithSbom(ctx context.Context, sbom *in_toto.CycloneDXStatement, imageName, imageTag string) (string, error) {
	p, err := c.GetProject(ctx, imageName, imageTag)
	if err != nil {
		return "", fmt.Errorf("failed to lookup project: %w", err)
	}

	if p == nil {
		p, err = c.CreateProject(ctx, imageName, imageTag, nil)
		if err != nil {
			return "", fmt.Errorf("failed to create project: %w", err)
		}
		if p == nil {
			return "", fmt.Errorf("created project is unexpectedly nil")
		}
	}

	if p.Uuid == "" {
		return "", fmt.Errorf("project UUID is empty")
	}

	if err = c.UploadSbom(ctx, p.Uuid, sbom); err != nil {
		var clientErr *ClientError
		if errors.As(err, &clientErr) {
			if deleteErr := c.DeleteProject(ctx, p.Uuid); deleteErr != nil {
				return "", fmt.Errorf("upload failed: %w (also failed to delete project: %v)", err, deleteErr)
			}
		}
		return "", fmt.Errorf("failed to upload SBOM: %w", err)
	}

	return p.Uuid, nil
}

func (c *dependencyTrackClient) CreateOrUpdateProjectWithSbom(ctx context.Context, sbom *in_toto.CycloneDXStatement, workloadRef *WorkloadRef) (string, error) {
	tags := workloadRef.tags()
	projectName := workloadRef.projectName()

	key := projectName + ":" + workloadRef.ImageTag
	var err error
	var p *client.Project
	l, _ := projectLocks.LoadOrStore(projectName+":"+workloadRef.ImageTag, &sync.Mutex{})
	lock := l.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()

	pc, found := projects.Get(key)
	if found {
		p = pc.(*client.Project)
	} else {
		p, err = c.GetProject(ctx, projectName, workloadRef.ImageTag)
		if err != nil {
			return "", err
		}
		if p != nil {
			projects.Set(key, p, cache.DefaultExpiration)
		}
	}

	if p != nil {
		p.Version = &workloadRef.ImageTag
		p.Tags = append(p.Tags, workloadRef.tags()...)
		p, err = c.UpdateProject(ctx, p)
		if err != nil {
			return "", fmt.Errorf("failed to update project: %w", err)
		}
		return p.Uuid, nil
	}

	p, err = c.CreateProject(ctx, projectName, workloadRef.ImageTag, tags)
	if err != nil {
		return "", fmt.Errorf("failed to create project: %w", err)
	}

	if err = c.UploadSbom(ctx, p.Uuid, sbom); err != nil {
		return "", err
	}

	return p.Uuid, nil
}

func (c *dependencyTrackClient) CreateProject(ctx context.Context, name, version string, tags []client.Tag) (*client.Project, error) {
	c.log.Debugf("creating project: %s", name+":"+version)
	p, err := withAuthContextValue(c, ctx, func(apiKeyCtx context.Context) (*client.Project, error) {
		active := true
		classifier := "APPLICATION"

		req := c.client.ProjectAPI.CreateProject(apiKeyCtx).Project(client.Project{
			Name:       &name,
			Active:     &active,
			Classifier: &classifier,
			Version:    &version,
			Tags:       tags,
			Parent:     nil,
		})

		project, resp, err := req.Execute()
		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusConflict {
				return nil, convertError(fmt.Errorf("project %s:%s already exists", name, version), "CreateProject", resp)
			}
			return nil, convertError(err, "CreateProject", resp)
		}

		return project, nil
	})
	if err != nil {
		return nil, err
	}
	projects.Set(name+":"+version, p, cache.DefaultExpiration)
	return p, nil
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
			return convertError(err, "UploadSbom", resp)
		}
		return nil
	})
}

// GetFindings Is this function lacking pagination for all findings in a project or do we not need it?
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
			return nil, convertError(err, "GetFindings", resp)
		}

		return findings, nil
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

			return nil, convertError(err, "GetProject", resp)
		}

		return project, err
	})
}

func (c *dependencyTrackClient) GetProjectsByTag(ctx context.Context, tag string, limit, offset int32) ([]client.Project, error) {
	return withAuthContextValue(c, ctx, func(apiKeyCtx context.Context) ([]client.Project, error) {
		return c.paginateProjects(apiKeyCtx, limit, offset, func(ctx context.Context, offset int32) ([]client.Project, error) {
			pageNumber := (offset / limit) + 1
			projects, resp, err := c.client.ProjectAPI.GetProjectsByTag(ctx, tag).
				PageSize(strconv.Itoa(int(limit))).
				PageNumber(strconv.Itoa(int(pageNumber))).
				Execute()

			if err != nil {
				return nil, convertError(err, "GetProjectsByTag", resp)
			}

			return projects, err
		})
	})
}

func (c *dependencyTrackClient) GetProjects(ctx context.Context, limit, offset int32) ([]client.Project, error) {
	return withAuthContextValue(c, ctx, func(apiKeyCtx context.Context) ([]client.Project, error) {
		return c.paginateProjects(apiKeyCtx, limit, offset, func(ctx context.Context, offset int32) ([]client.Project, error) {
			pageNumber := (offset / limit) + 1
			// convert to string from int32
			projects, resp, err := c.client.ProjectAPI.GetProjects(ctx).
				PageSize(strconv.Itoa(int(limit))).
				PageNumber(strconv.Itoa(int(pageNumber))).
				Execute()
			return projects, convertError(err, "GetProjects", resp)
		})
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
			AnalysisRequest(analysisRequest).
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
			return nil, convertError(err, "GetAnalysisTrailForImage", resp)
		}
		return trail, nil
	})
}

func (c *dependencyTrackClient) UpdateProject(ctx context.Context, p *client.Project) (*client.Project, error) {
	c.log.Debugf("updating project: %s", *p.Name+":"+*p.Version)
	p, err := withAuthContextValue(c, ctx, func(apiKeyCtx context.Context) (*client.Project, error) {
		project, resp, err := c.client.ProjectAPI.UpdateProject(apiKeyCtx).Project(*p).Execute()
		if err != nil {
			return nil, convertError(err, "UpdateProject", resp)
		}
		return project, nil
	})
	if err != nil {
		return nil, err
	}
	projects.Set(p.Uuid, p, cache.DefaultExpiration)
	return p, nil
}

func (c *dependencyTrackClient) DeleteProject(ctx context.Context, uuid string) error {
	return c.withAuthContext(ctx, func(apiKeyCtx context.Context) error {
		resp, err := c.client.ProjectAPI.DeleteProject(apiKeyCtx, uuid).Execute()
		if err != nil {
			return convertError(err, "DeleteProject", resp)
		}
		return nil
	})
}

func (c *dependencyTrackClient) withAuthContext(ctx context.Context, fn func(ctx context.Context) error) error {
	apiKeyCtx, err := c.auth.ContextHeaders(ctx)
	if err != nil {
		return fmt.Errorf("auth error: %w", err)
	}
	return fn(apiKeyCtx)
}

func convertError(err error, msg string, resp *http.Response) error {
	switch {
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return ClientError{fmt.Errorf("%s, err=%w, statuscode=%d, body=%s", msg, err, resp.StatusCode, parseErrorResponseBody(resp))}
	case resp.StatusCode >= 500:
		return ServerError{fmt.Errorf("%s, err=%w, statuscode=%d, body=%s", msg, err, resp.StatusCode, parseErrorResponseBody(resp))}
	default:
		return nil
	}
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

func withAuthContextValue[T any](c *dependencyTrackClient, ctx context.Context, fn func(ctx context.Context) (T, error)) (T, error) {
	apiKeyCtx, err := c.auth.ContextHeaders(ctx)
	if err != nil {
		var zero T
		return zero, fmt.Errorf("auth error: %w", err)
	}
	return fn(apiKeyCtx)
}

func (w *WorkloadRef) projectName() string {
	return w.ImageName
}

func (w *WorkloadRef) tags() []client.Tag {
	stringTags := []string{
		fmt.Sprintf("workload:%s", w.Cluster+"|"+w.Namespace+"|"+w.Type+"|"+w.Name),
	}

	tags := make([]client.Tag, 0)
	for _, tag := range stringTags {
		tags = append(tags, client.Tag{
			Name: &tag,
		})
	}
	return tags
}

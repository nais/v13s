package dependencytrack

import (
	"context"
	"fmt"
	"github.com/nais/v13s/internal/dependencytrack/auth"
	"github.com/nais/v13s/internal/dependencytrack/client"
	"io"
	"net/url"
	"strings"
)

var _ Client = &dependencyTrackClient{}

type Client interface {
	GetFindings(ctx context.Context, uuid string, suppressed bool) ([]client.Finding, error)
	GetProjectsByTag(ctx context.Context, tag string, limit, offset int32) ([]client.Project, error)
	GetProject(ctx context.Context, name, version string) (*client.Project, error)
	GetProjects(ctx context.Context, limit, offset int32) ([]client.Project, error)
}

type dependencyTrackClient struct {
	client *client.APIClient
	auth   auth.Auth
}

func NewClient(url string, team auth.Team, username auth.Username, password auth.Password) (Client, error) {
	if url == "" {
		return nil, fmt.Errorf("NewClient: URL cannot be empty")
	}

	clientConfig := setupConfig(url)
	apiClient := client.NewAPIClient(clientConfig)
	userPasSource := auth.NewUsernamePasswordSource(username, password, apiClient)
	return &dependencyTrackClient{
		client: apiClient,
		auth:   auth.NewApiKeySource(team, userPasSource, apiClient),
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

func (c *dependencyTrackClient) getAPIKeyContext(ctx context.Context) (context.Context, error) {
	apiKeyCtx, err := c.auth.ContextHeaders(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get API key: %w", err)
	}
	return apiKeyCtx, nil
}

func (c *dependencyTrackClient) GetFindings(ctx context.Context, uuid string, suppressed bool) ([]client.Finding, error) {
	apiKeyCtx, err := c.getAPIKeyContext(ctx)
	if err != nil {
		return nil, err
	}

	findings, _, err := c.client.FindingAPI.GetFindingsByProject(apiKeyCtx, uuid).
		Suppressed(suppressed).
		Execute()

	if err != nil {
		return nil, fmt.Errorf("failed to get findings for project %s: %w", uuid, err)
	}

	return findings, nil
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
	apiKeyCtx, err := c.getAPIKeyContext(ctx)
	if err != nil {
		return nil, err
	}

	return c.paginateProjects(apiKeyCtx, limit, offset, func(ctx context.Context, offset int32) ([]client.Project, error) {
		pageNumber := (offset / limit) + 1
		projects, _, err := c.client.ProjectAPI.GetProjectsByTag(ctx, tag).
			PageSize(limit).
			PageNumber(pageNumber).
			Execute()
		return projects, err
	})
}

func (c *dependencyTrackClient) GetProject(ctx context.Context, name, version string) (*client.Project, error) {
	apiKeyCtx, err := c.getAPIKeyContext(ctx)
	if err != nil {
		return nil, err
	}

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
}

func (c *dependencyTrackClient) GetProjects(ctx context.Context, limit, offset int32) ([]client.Project, error) {
	apiKeyCtx, err := c.getAPIKeyContext(ctx)
	if err != nil {
		return nil, err
	}

	return c.paginateProjects(apiKeyCtx, limit, offset, func(ctx context.Context, offset int32) ([]client.Project, error) {
		pageNumber := (offset / limit) + 1
		projects, _, err := c.client.ProjectAPI.GetProjects(ctx).
			PageSize(limit).
			PageNumber(pageNumber).
			Execute()
		return projects, err
	})
}

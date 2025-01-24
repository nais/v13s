package dependencytrack

import (
	"context"

	"github.com/nais/v13s/internal/dependencytrack/client"
)

const ClientXApiKeyHeader = "X-Api-Key"

type Client struct {
	client *client.APIClient
}

type Vulnerability struct {
	UUID         string `json:"uuid"`
	VulnId       string `json:"vulnId"`
	Severity     string `json:"severity"`
	SeverityRank int    `json:"severityRank"`
	Source       string `json:"source"`
	Title        string `json:"title"`
}

func setupConfig(apiKey, url string) *client.Configuration {
	cfg := client.NewConfiguration()
	cfg.AddDefaultHeader(ClientXApiKeyHeader, apiKey)
	cfg.Scheme = "https"
	cfg.Servers = client.ServerConfigurations{
		{
			URL: url,
		},
	}
	return cfg
}

func NewClient(apiKey, url string) (*Client, error) {
	return &Client{client.NewAPIClient(setupConfig(apiKey, url))}, nil
}

func (c *Client) GetFindings(ctx context.Context, uuid string, suppressed bool) ([]client.Finding, error) {
	p, _, err := c.client.FindingAPI.GetFindingsByProject(ctx, uuid).
		Suppressed(suppressed).
		Execute()
	return p, err
}

func (c *Client) paginateProjects(ctx context.Context, limit, offset int32, callFunc func(ctx context.Context, offset int32) ([]client.Project, error)) ([]client.Project, error) {
	var allProjects []client.Project

	for {
		p, err := callFunc(ctx, offset)
		if err != nil {
			return nil, err
		}

		allProjects = append(allProjects, p...)

		if len(p) < int(limit) {
			break
		}

		offset += limit
	}

	return allProjects, nil
}

func (c *Client) GetProjectsByTag(ctx context.Context, tag string, limit, offset int32) ([]client.Project, error) {
	return c.paginateProjects(ctx, limit, offset, func(ctx context.Context, offset int32) ([]client.Project, error) {
		pageNumber := (offset / limit) + 1
		p, _, err := c.client.ProjectAPI.GetProjectsByTag(ctx, tag).
			PageSize(limit).
			PageNumber(pageNumber).
			Execute()
		return p, err
	})
}

func (c *Client) GetProject(ctx context.Context, name, version string) (*client.Project, error) {
	p, _, err := c.client.ProjectAPI.GetProjectByNameAndVersion(ctx).
		Name(name).
		Version(version).
		Execute()
	return p, err
}

func (c *Client) GetProjects(ctx context.Context, limit, offset int32) ([]client.Project, error) {
	return c.paginateProjects(ctx, limit, offset, func(ctx context.Context, offset int32) ([]client.Project, error) {
		pageNumber := (offset / limit) + 1
		p, _, err := c.client.ProjectAPI.GetProjects(ctx).
			PageSize(limit).
			PageNumber(pageNumber).
			Execute()
		return p, err
	})
}

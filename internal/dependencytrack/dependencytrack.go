package dependencytrack

import (
	"context"
	"github.com/nais/v13s/internal/dependencytrack/client"
)

const ClientXApiKeyHeader = "X-Api-Key"

type Client struct {
	client *client.APIClient
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

func (c *Client) paginateProjects(ctx context.Context, callFunc func(ctx context.Context, limit, offset int) ([]client.Project, error)) ([]client.Project, error) {
	var allProjects []client.Project
	pageSize := 100
	offset := 0

	for {
		p, err := callFunc(ctx, pageSize, offset)
		if err != nil {
			return nil, err
		}

		allProjects = append(allProjects, p...)

		if len(p) < pageSize {
			break
		}

		offset += pageSize
	}

	return allProjects, nil
}

func (c *Client) GetProjectsByTag(ctx context.Context, tag string) ([]client.Project, error) {
	return c.paginateProjects(ctx, func(ctx context.Context, limit, offset int) ([]client.Project, error) {
		pageNumber := (offset / limit) + 1
		p, _, err := c.client.ProjectAPI.GetProjectsByTag(ctx, tag).
			PageSize(limit).
			PageNumber(pageNumber).
			Execute()
		return p, err
	})
}

func (c *Client) GetProjects(ctx context.Context) ([]client.Project, error) {
	return c.paginateProjects(ctx, func(ctx context.Context, limit, offset int) ([]client.Project, error) {
		pageNumber := (offset / limit) + 1
		p, _, err := c.client.ProjectAPI.GetProjects(ctx).
			PageSize(limit).
			PageNumber(pageNumber).
			Execute()
		return p, err
	})
}

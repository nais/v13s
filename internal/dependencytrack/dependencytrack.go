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

// Should use pages returned from the API to get all projects
func (c *Client) GetProjects(ctx context.Context) ([]client.Project, error) {
	p, _, err := c.client.ProjectAPI.GetProjects(ctx).Execute()
	if err != nil {
		return nil, err
	}
	return p, nil
}

// Should use pages returned from the API to get all projects
func (c *Client) GetProjectsByTag(ctx context.Context, tag string) ([]client.Project, error) {
	p, _, err := c.client.ProjectAPI.GetProjectsByTag(ctx, tag).Execute()
	if err != nil {
		return nil, err
	}
	return p, nil
}

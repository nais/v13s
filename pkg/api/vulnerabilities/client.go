package vulnerabilities

import (
	"context"
	"fmt"
	"google.golang.org/grpc"
)

type Client interface {
	Close() error
	ListVulnerabilitySummaries(ctx context.Context, opts ...Option) (*ListVulnerabilitySummariesResponse, error)
	GetVulnerabilitySummaryResponse(ctx context.Context, opts ...Option) (*GetVulnerabilitySummaryResponse, error)
	ListVulnerabilities(ctx context.Context, opts ...Option) (*ListVulnerabilitiesResponse, error)
}

var _ Client = &client{}

type client struct {
	c    VulnerabilitiesClient
	conn *grpc.ClientConn
}

func NewClient(target string, opts ...grpc.DialOption) (Client, error) {
	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gRPC server: %w", err)
	}
	return &client{
		c:    NewVulnerabilitiesClient(conn),
		conn: conn,
	}, nil
}

func (c *client) Close() error {
	return c.conn.Close()
}

func (c *client) ListVulnerabilitySummaries(ctx context.Context, opts ...Option) (*ListVulnerabilitySummariesResponse, error) {
	o := applyOptions(opts...)

	return c.c.ListVulnerabilitySummaries(ctx, &ListVulnerabilitySummariesRequest{
		Filter: o.filter,
	}, o.callOptions...)
}

func (c *client) GetVulnerabilitySummaryResponse(ctx context.Context, opts ...Option) (*GetVulnerabilitySummaryResponse, error) {
	o := applyOptions(opts...)

	return c.c.GetVulnerabilitySummary(
		ctx,
		&GetVulnerabilitySummaryRequest{
			Filter: o.filter,
		},
	)
}

func (c *client) ListVulnerabilities(ctx context.Context, opts ...Option) (*ListVulnerabilitiesResponse, error) {
	o := applyOptions(opts...)

	return c.c.ListVulnerabilities(
		ctx,
		&ListVulnerabilitiesRequest{
			Suppressed: &o.Suppressed,
			Filter:     o.filter,
		},
	)
}

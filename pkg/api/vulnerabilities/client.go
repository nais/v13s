package vulnerabilities

import (
	"context"
	"fmt"
	"google.golang.org/grpc"
)

type Client interface {
	Close() error
	ListVulnerabilitySummaries(ctx context.Context, opts ...Option) (*ListWorkloadSummariesResponse, error)
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

func (c *client) ListVulnerabilitySummaries(ctx context.Context, opts ...Option) (*ListWorkloadSummariesResponse, error) {
	o := applyOptions(opts...)

	return c.c.ListVulnerabilitySummaries(ctx, &ListWorkloadSummariesRequest{
		Filter: o.filter,
	}, o.callOptions...)
}

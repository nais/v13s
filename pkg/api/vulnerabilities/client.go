package vulnerabilities

import (
	"context"
	"fmt"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"

	"google.golang.org/grpc"
)

type Client interface {
	Close() error
	ListVulnerabilitySummaries(ctx context.Context, opts ...Option) (*ListVulnerabilitySummariesResponse, error)
	GetVulnerabilitySummary(ctx context.Context, opts ...Option) (*GetVulnerabilitySummaryResponse, error)
	GetVulnerabilitySummaryForImage(ctx context.Context, imageName, imageTag string) (*GetVulnerabilitySummaryForImageResponse, error)
	ListVulnerabilitiesForImage(ctx context.Context, imageName, imageTag string, includeSuppressed bool) (*ListVulnerabilitiesForImageResponse, error)
	ListVulnerabilities(ctx context.Context, opts ...Option) (*ListVulnerabilitiesResponse, error)
	management.ManagementClient
}

var _ Client = &client{}

type client struct {
	c    VulnerabilitiesClient
	m    management.ManagementClient
	conn *grpc.ClientConn
}

func (c *client) ListVulnerabilitiesForImage(ctx context.Context, imageName, imageTag string, includeSuppressed bool) (*ListVulnerabilitiesForImageResponse, error) {
	return c.c.ListVulnerabilitiesForImage(ctx, &ListVulnerabilitiesForImageRequest{
		ImageName:         imageName,
		ImageTag:          imageTag,
		IncludeSuppressed: includeSuppressed,
	})
}

func (c *client) GetVulnerabilitySummaryForImage(ctx context.Context, imageName, imageTag string) (*GetVulnerabilitySummaryForImageResponse, error) {
	return c.c.GetVulnerabilitySummaryForImage(ctx, &GetVulnerabilitySummaryForImageRequest{
		ImageName: imageName,
		ImageTag:  imageTag,
	})
}

func (c *client) RegisterWorkload(ctx context.Context, in *management.RegisterWorkloadRequest, opts ...grpc.CallOption) (*management.RegisterWorkloadResponse, error) {
	return c.m.RegisterWorkload(ctx, in, opts...)
}

func NewClient(target string, opts ...grpc.DialOption) (Client, error) {
	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gRPC server: %w", err)
	}
	return &client{
		c:    NewVulnerabilitiesClient(conn),
		m:    management.NewManagementClient(conn),
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
		Limit:  o.limit,
		Offset: o.offset,
	}, o.callOptions...)
}

func (c *client) GetVulnerabilitySummary(ctx context.Context, opts ...Option) (*GetVulnerabilitySummaryResponse, error) {
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
			Filter:     o.filter,
			Limit:      o.limit,
			Offset:     o.offset,
			Suppressed: &o.suppressed,
		},
	)
}

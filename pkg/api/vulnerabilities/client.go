package vulnerabilities

import (
	"context"
	"fmt"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"
	"google.golang.org/grpc"
)

type Client interface {
	Close() error
	ListVulnerabilities(ctx context.Context, opts ...Option) (*ListVulnerabilitiesResponse, error)
	ListVulnerabilitiesForImage(ctx context.Context, imageName, imageTag string, opts ...Option) (*ListVulnerabilitiesForImageResponse, error)
	ListSuppressedVulnerabilities(ctx context.Context, opts ...Option) (*ListSuppressedVulnerabilitiesResponse, error)
	ListVulnerabilitySummaries(ctx context.Context, opts ...Option) (*ListVulnerabilitySummariesResponse, error)
	GetVulnerabilitySummary(ctx context.Context, opts ...Option) (*GetVulnerabilitySummaryResponse, error)
	GetVulnerabilitySummaryForImage(ctx context.Context, imageName, imageTag string) (*GetVulnerabilitySummaryForImageResponse, error)
	GetVulnerabilityById(ctx context.Context, id string) (*GetVulnerabilityByIdResponse, error)
	SuppressVulnerability(ctx context.Context, id, reason, suppressedBy string, state SuppressState, suppress bool) error
	management.ManagementClient
}

var _ Client = &client{}

type client struct {
	v    VulnerabilitiesClient
	m    management.ManagementClient
	conn *grpc.ClientConn
}

func NewClient(target string, opts ...grpc.DialOption) (Client, error) {
	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gRPC server: %w", err)
	}
	return &client{
		v:    NewVulnerabilitiesClient(conn),
		m:    management.NewManagementClient(conn),
		conn: conn,
	}, nil
}

func (c *client) Close() error {
	return c.conn.Close()
}

func (c *client) ListVulnerabilities(ctx context.Context, opts ...Option) (*ListVulnerabilitiesResponse, error) {
	o := applyOptions(opts...)
	return c.v.ListVulnerabilities(
		ctx,
		&ListVulnerabilitiesRequest{
			Filter:            o.filter,
			IncludeSuppressed: &o.includeSuppressed,
			Limit:             o.limit,
			Offset:            o.offset,
			OrderBy:           o.orderBy,
		},
	)
}

func (c *client) ListVulnerabilitiesForImage(ctx context.Context, imageName, imageTag string, opts ...Option) (*ListVulnerabilitiesForImageResponse, error) {
	o := applyOptions(opts...)
	return c.v.ListVulnerabilitiesForImage(ctx, &ListVulnerabilitiesForImageRequest{
		ImageName:         imageName,
		ImageTag:          imageTag,
		IncludeSuppressed: o.includeSuppressed,
		Limit:             o.limit,
		Offset:            o.offset,
		OrderBy:           o.orderBy,
	}, o.callOptions...)
}

func (c *client) ListSuppressedVulnerabilities(ctx context.Context, opts ...Option) (*ListSuppressedVulnerabilitiesResponse, error) {
	o := applyOptions(opts...)
	return c.v.ListSuppressedVulnerabilities(ctx, &ListSuppressedVulnerabilitiesRequest{
		Filter:  o.filter,
		Limit:   o.limit,
		Offset:  o.offset,
		OrderBy: o.orderBy,
	})
}

func (c *client) ListVulnerabilitySummaries(ctx context.Context, opts ...Option) (*ListVulnerabilitySummariesResponse, error) {
	o := applyOptions(opts...)
	return c.v.ListVulnerabilitySummaries(ctx, &ListVulnerabilitySummariesRequest{
		Filter:  o.filter,
		Limit:   o.limit,
		Offset:  o.offset,
		OrderBy: o.orderBy,
		Since:   o.since,
	}, o.callOptions...)
}

func (c *client) GetVulnerabilitySummary(ctx context.Context, opts ...Option) (*GetVulnerabilitySummaryResponse, error) {
	o := applyOptions(opts...)

	return c.v.GetVulnerabilitySummary(
		ctx,
		&GetVulnerabilitySummaryRequest{
			Filter: o.filter,
		},
	)
}

func (c *client) GetVulnerabilitySummaryForImage(ctx context.Context, imageName, imageTag string) (*GetVulnerabilitySummaryForImageResponse, error) {
	return c.v.GetVulnerabilitySummaryForImage(ctx, &GetVulnerabilitySummaryForImageRequest{
		ImageName: imageName,
		ImageTag:  imageTag,
	})
}

func (c *client) GetVulnerabilityById(ctx context.Context, id string) (*GetVulnerabilityByIdResponse, error) {
	return c.v.GetVulnerabilityById(ctx, &GetVulnerabilityByIdRequest{
		Id: id,
	})
}

func (c *client) SuppressVulnerability(ctx context.Context, id, reason, suppressedBy string, state SuppressState, suppress bool) error {
	_, err := c.v.SuppressVulnerability(ctx, &SuppressVulnerabilityRequest{
		Id:           id,
		Reason:       &reason,
		SuppressedBy: &suppressedBy,
		State:        state,
		Suppress:     &suppress,
	})
	return err
}

func (c *client) RegisterWorkload(ctx context.Context, in *management.RegisterWorkloadRequest, opts ...grpc.CallOption) (*management.RegisterWorkloadResponse, error) {
	return c.m.RegisterWorkload(ctx, in, opts...)
}

func (c *client) TriggerSync(ctx context.Context, in *management.TriggerSyncRequest, opts ...grpc.CallOption) (*management.TriggerSyncResponse, error) {
	return c.m.TriggerSync(ctx, in, opts...)
}

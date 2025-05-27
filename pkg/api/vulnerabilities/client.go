package vulnerabilities

import (
	"context"
	"fmt"

	"github.com/nais/v13s/pkg/api/vulnerabilitiespb"
	"github.com/nais/v13s/pkg/api/vulnerabilitiespb/management"
	"google.golang.org/grpc"
)

type Client interface {
	Close() error
	ListVulnerabilities(ctx context.Context, opts ...Option) (*vulnerabilitiespb.ListVulnerabilitiesResponse, error)
	ListVulnerabilitiesForImage(ctx context.Context, imageName, imageTag string, opts ...Option) (*vulnerabilitiespb.ListVulnerabilitiesForImageResponse, error)
	ListSuppressedVulnerabilities(ctx context.Context, opts ...Option) (*vulnerabilitiespb.ListSuppressedVulnerabilitiesResponse, error)
	ListVulnerabilitySummaries(ctx context.Context, opts ...Option) (*vulnerabilitiespb.ListVulnerabilitySummariesResponse, error)
	GetVulnerabilitySummary(ctx context.Context, opts ...Option) (*vulnerabilitiespb.GetVulnerabilitySummaryResponse, error)
	GetVulnerabilitySummaryTimeSeries(ctx context.Context, opts ...Option) (*vulnerabilitiespb.GetVulnerabilitySummaryTimeSeriesResponse, error)
	GetVulnerabilitySummaryForImage(ctx context.Context, imageName, imageTag string) (*vulnerabilitiespb.GetVulnerabilitySummaryForImageResponse, error)
	GetVulnerabilityById(ctx context.Context, id string) (*vulnerabilitiespb.GetVulnerabilityByIdResponse, error)
	SuppressVulnerability(ctx context.Context, id, reason, suppressedBy string, state vulnerabilitiespb.SuppressState, suppress bool) error
	management.ManagementClient
}

var _ Client = &client{}

type client struct {
	v    vulnerabilitiespb.VulnerabilitiesClient
	m    management.ManagementClient
	conn *grpc.ClientConn
}

func NewClient(target string, opts ...grpc.DialOption) (Client, error) {
	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gRPC server: %w", err)
	}
	return &client{
		v:    vulnerabilitiespb.NewVulnerabilitiesClient(conn),
		m:    management.NewManagementClient(conn),
		conn: conn,
	}, nil
}

func (c *client) Close() error {
	return c.conn.Close()
}

func (c *client) ListVulnerabilities(ctx context.Context, opts ...Option) (*vulnerabilitiespb.ListVulnerabilitiesResponse, error) {
	o := applyOptions(opts...)
	return c.v.ListVulnerabilities(
		ctx,
		&vulnerabilitiespb.ListVulnerabilitiesRequest{
			Filter:            o.Filter,
			IncludeSuppressed: &o.IncludeSuppressed,
			Limit:             o.Limit,
			Offset:            o.Offset,
			OrderBy:           o.OrderBy,
		},
	)
}

func (c *client) ListVulnerabilitiesForImage(ctx context.Context, imageName, imageTag string, opts ...Option) (*vulnerabilitiespb.ListVulnerabilitiesForImageResponse, error) {
	o := applyOptions(opts...)
	return c.v.ListVulnerabilitiesForImage(ctx, &vulnerabilitiespb.ListVulnerabilitiesForImageRequest{
		ImageName:         imageName,
		ImageTag:          imageTag,
		IncludeSuppressed: o.IncludeSuppressed,
		Limit:             o.Limit,
		Offset:            o.Offset,
		OrderBy:           o.OrderBy,
	}, o.CallOptions...)
}

func (c *client) ListSuppressedVulnerabilities(ctx context.Context, opts ...Option) (*vulnerabilitiespb.ListSuppressedVulnerabilitiesResponse, error) {
	o := applyOptions(opts...)
	return c.v.ListSuppressedVulnerabilities(ctx, &vulnerabilitiespb.ListSuppressedVulnerabilitiesRequest{
		Filter:  o.Filter,
		Limit:   o.Limit,
		Offset:  o.Offset,
		OrderBy: o.OrderBy,
	})
}

func (c *client) ListVulnerabilitySummaries(ctx context.Context, opts ...Option) (*vulnerabilitiespb.ListVulnerabilitySummariesResponse, error) {
	o := applyOptions(opts...)
	return c.v.ListVulnerabilitySummaries(ctx, &vulnerabilitiespb.ListVulnerabilitySummariesRequest{
		Filter:  o.Filter,
		Limit:   o.Limit,
		Offset:  o.Offset,
		OrderBy: o.OrderBy,
		Since:   o.Since,
	}, o.CallOptions...)
}

func (c *client) GetVulnerabilitySummary(ctx context.Context, opts ...Option) (*vulnerabilitiespb.GetVulnerabilitySummaryResponse, error) {
	o := applyOptions(opts...)
	return c.v.GetVulnerabilitySummary(
		ctx,
		&vulnerabilitiespb.GetVulnerabilitySummaryRequest{
			Filter: o.Filter,
		},
	)
}

func (c *client) GetVulnerabilitySummaryTimeSeries(ctx context.Context, opts ...Option) (*vulnerabilitiespb.GetVulnerabilitySummaryTimeSeriesResponse, error) {
	o := applyOptions(opts...)
	return c.v.GetVulnerabilitySummaryTimeSeries(ctx, &vulnerabilitiespb.GetVulnerabilitySummaryTimeSeriesRequest{
		Filter: o.Filter,
		Since:  o.Since,
	})
}

func (c *client) GetVulnerabilitySummaryForImage(ctx context.Context, imageName, imageTag string) (*vulnerabilitiespb.GetVulnerabilitySummaryForImageResponse, error) {
	return c.v.GetVulnerabilitySummaryForImage(ctx, &vulnerabilitiespb.GetVulnerabilitySummaryForImageRequest{
		ImageName: imageName,
		ImageTag:  imageTag,
	})
}

func (c *client) GetVulnerabilityById(ctx context.Context, id string) (*vulnerabilitiespb.GetVulnerabilityByIdResponse, error) {
	return c.v.GetVulnerabilityById(ctx, &vulnerabilitiespb.GetVulnerabilityByIdRequest{
		Id: id,
	})
}

func (c *client) SuppressVulnerability(ctx context.Context, id, reason, suppressedBy string, state vulnerabilitiespb.SuppressState, suppress bool) error {
	_, err := c.v.SuppressVulnerability(ctx, &vulnerabilitiespb.SuppressVulnerabilityRequest{
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

func (c *client) Resync(ctx context.Context, in *management.ResyncRequest, opts ...grpc.CallOption) (*management.ResyncResponse, error) {
	return c.m.Resync(ctx, in, opts...)
}

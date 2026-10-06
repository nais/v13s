package vulnerabilities

import (
	"context"
	"fmt"

	"github.com/nais/v13s/pkg/api/vulnerabilities/management"
	"google.golang.org/grpc"
)

type Client interface {
	Close() error
	ListVulnerabilitiesForImage(ctx context.Context, imageName, imageTag string, opts ...Option) (*ListVulnerabilitiesForImageResponse, error)
	ListVulnerabilitySummaries(ctx context.Context, opts ...Option) (*ListVulnerabilitySummariesResponse, error)
	ListWorkloadsForVulnerabilityById(ctx context.Context, id string) (*ListWorkloadsForVulnerabilityByIdResponse, error)
	ListWorkloadsForVulnerability(ctx context.Context, vulnerabilityFilter VulnerabilityFilter, opts ...Option) (*ListWorkloadsForVulnerabilityResponse, error)
	ListCveSummaries(ctx context.Context, opts ...Option) (*ListCveSummariesResponse, error)
	ListMeanTimeToFixTrendBySeverity(ctx context.Context, opts ...Option) (*ListMeanTimeToFixTrendBySeverityResponse, error)
	GetVulnerabilitySummary(ctx context.Context, opts ...Option) (*GetVulnerabilitySummaryResponse, error)
	GetVulnerabilitySummaries(ctx context.Context, namespaces []string, opts ...Option) (*GetVulnerabilitySummariesResponse, error)
	GetVulnerabilitySummaryTimeSeries(ctx context.Context, opts ...Option) (*GetVulnerabilitySummaryTimeSeriesResponse, error)
	GetVulnerabilitySummaryForImage(ctx context.Context, imageName, imageTag string) (*GetVulnerabilitySummaryForImageResponse, error)
	GetVulnerabilityById(ctx context.Context, id string) (*GetVulnerabilityByIdResponse, error)
	GetCve(ctx context.Context, id string) (*GetCveResponse, error)
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

func (c *client) ListVulnerabilitiesForImage(ctx context.Context, imageName, imageTag string, opts ...Option) (*ListVulnerabilitiesForImageResponse, error) {
	o := applyOptions(opts...)
	return c.v.ListVulnerabilitiesForImage(ctx, &ListVulnerabilitiesForImageRequest{
		ImageName:         imageName,
		ImageTag:          imageTag,
		IncludeSuppressed: o.IncludeSuppressed,
		Limit:             o.Limit,
		Offset:            o.Offset,
		OrderBy:           o.OrderBy,
		Since:             o.Since,
		Severity:          o.Severity,
		Priorities:        o.Filter.GetPriorities(),
		HasKev:            o.Filter.HasKev,
	}, o.CallOptions...)
}

func (c *client) ListVulnerabilitySummaries(ctx context.Context, opts ...Option) (*ListVulnerabilitySummariesResponse, error) {
	o := applyOptions(opts...)
	return c.v.ListVulnerabilitySummaries(ctx, &ListVulnerabilitySummariesRequest{
		Filter:       o.Filter,
		Limit:        o.Limit,
		Offset:       o.Offset,
		OrderBy:      o.OrderBy,
		Since:        o.Since,
		SbomStatuses: o.SbomStatuses,
	}, o.CallOptions...)
}

func (c *client) ListWorkloadsForVulnerabilityById(ctx context.Context, id string) (*ListWorkloadsForVulnerabilityByIdResponse, error) {
	return c.v.ListWorkloadsForVulnerabilityById(ctx, &ListWorkloadsForVulnerabilityByIdRequest{
		Id: id,
	})
}

func (c *client) ListWorkloadsForVulnerability(ctx context.Context, vulnerabilityFilter VulnerabilityFilter, opts ...Option) (*ListWorkloadsForVulnerabilityResponse, error) {
	o := applyOptions(opts...)
	return c.v.ListWorkloadsForVulnerability(ctx, &ListWorkloadsForVulnerabilityRequest{
		Filter:            o.Filter,
		Limit:             o.Limit,
		Offset:            o.Offset,
		OrderBy:           o.OrderBy,
		CveIds:            vulnerabilityFilter.CveIds,
		CvssScore:         vulnerabilityFilter.CvssScore,
		ExcludeNamespaces: o.ExcludeNamespaces,
		ExcludeClusters:   o.ExcludeClusters,
		IncludeSuppressed: &o.IncludeSuppressed,
	}, o.CallOptions...)
}

func (c *client) ListCveSummaries(ctx context.Context, opts ...Option) (*ListCveSummariesResponse, error) {
	o := applyOptions(opts...)
	return c.v.ListCveSummaries(ctx, &ListCveSummariesRequest{
		Filter:            o.Filter,
		Limit:             o.Limit,
		Offset:            o.Offset,
		OrderBy:           o.OrderBy,
		ExcludeNamespaces: o.ExcludeNamespaces,
		ExcludeClusters:   o.ExcludeClusters,
		IncludeSuppressed: &o.IncludeSuppressed,
	}, o.CallOptions...)
}

func (c *client) ListMeanTimeToFixTrendBySeverity(ctx context.Context, opts ...Option) (*ListMeanTimeToFixTrendBySeverityResponse, error) {
	o := applyOptions(opts...)
	return c.v.ListMeanTimeToFixTrendBySeverity(ctx, &ListMeanTimeToFixTrendBySeverityRequest{
		Filter:    o.Filter,
		Since:     o.Since,
		SinceType: o.SinceType,
	}, o.CallOptions...)
}

func (c *client) GetVulnerabilitySummary(ctx context.Context, opts ...Option) (*GetVulnerabilitySummaryResponse, error) {
	o := applyOptions(opts...)
	return c.v.GetVulnerabilitySummary(
		ctx,
		&GetVulnerabilitySummaryRequest{
			Filter: o.Filter,
		},
	)
}

func (c *client) GetVulnerabilitySummaries(ctx context.Context, namespaces []string, opts ...Option) (*GetVulnerabilitySummariesResponse, error) {
	o := applyOptions(opts...)
	return c.v.GetVulnerabilitySummaries(ctx, &GetVulnerabilitySummariesRequest{
		Namespaces: namespaces,
		Filter:     o.Filter,
	}, o.CallOptions...)
}

func (c *client) GetVulnerabilitySummaryTimeSeries(ctx context.Context, opts ...Option) (*GetVulnerabilitySummaryTimeSeriesResponse, error) {
	o := applyOptions(opts...)
	return c.v.GetVulnerabilitySummaryTimeSeries(ctx, &GetVulnerabilitySummaryTimeSeriesRequest{
		Filter: o.Filter,
		Since:  o.Since,
	})
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

func (c *client) GetCve(ctx context.Context, id string) (*GetCveResponse, error) {
	return c.v.GetCve(ctx, &GetCveRequest{
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

func (c *client) GetWorkloadStatus(ctx context.Context, in *management.GetWorkloadStatusRequest, opts ...grpc.CallOption) (*management.GetWorkloadStatusResponse, error) {
	return c.m.GetWorkloadStatus(ctx, in, opts...)
}

func (c *client) GetWorkloadJobs(ctx context.Context, in *management.GetWorkloadJobsRequest, opts ...grpc.CallOption) (*management.GetWorkloadJobsResponse, error) {
	return c.m.GetWorkloadJobs(ctx, in, opts...)
}

func (c *client) Resync(ctx context.Context, in *management.ResyncRequest, opts ...grpc.CallOption) (*management.ResyncResponse, error) {
	return c.m.Resync(ctx, in, opts...)
}

func (c *client) DeleteWorkload(ctx context.Context, in *management.DeleteWorkloadRequest, opts ...grpc.CallOption) (*management.DeleteWorkloadResponse, error) {
	return c.m.DeleteWorkload(ctx, in, opts...)
}

package grpcvulnerabilities

import (
	"context"
	"testing"

	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type invalidLabelFilterCase struct {
	name   string
	filter []*vulnerabilities.LabelFilter
}

type unsupportedLabelFilterCase struct {
	name string
	call func(*Server, *vulnerabilities.Filter) error
}

func TestSummaryLabelsRejectInvalidInput(t *testing.T) {
	for _, tt := range []invalidLabelFilterCase{
		{"nil filter", []*vulnerabilities.LabelFilter{nil}},
		{"empty key", []*vulnerabilities.LabelFilter{{}}},
		{"invalid key", []*vulnerabilities.LabelFilter{{Key: "bad key"}}},
		{"invalid value", []*vulnerabilities.LabelFilter{{Key: "owner", Value: new("bad value")}}},
		{"platform key", []*vulnerabilities.LabelFilter{{Key: "team"}}},
		{"hidden value", []*vulnerabilities.LabelFilter{{Key: "app.kubernetes.io/managed-by", Value: new("console")}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			response, err := (&Server{}).ListVulnerabilitySummaries(context.Background(), &vulnerabilities.ListVulnerabilitySummariesRequest{
				Filter: &vulnerabilities.Filter{Labels: tt.filter},
			})
			assert.Nil(t, response)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

func TestLabelFiltersRejectedOutsideSummaryList(t *testing.T) {
	ctx := context.Background()
	for _, tt := range []unsupportedLabelFilterCase{
		{"GetVulnerabilitySummary", func(s *Server, f *vulnerabilities.Filter) error {
			_, err := s.GetVulnerabilitySummary(ctx, &vulnerabilities.GetVulnerabilitySummaryRequest{Filter: f})
			return err
		}},
		{"GetVulnerabilitySummaries", func(s *Server, f *vulnerabilities.Filter) error {
			_, err := s.GetVulnerabilitySummaries(ctx, &vulnerabilities.GetVulnerabilitySummariesRequest{Filter: f})
			return err
		}},
		{"GetVulnerabilitySummaryTimeSeries", func(s *Server, f *vulnerabilities.Filter) error {
			_, err := s.GetVulnerabilitySummaryTimeSeries(ctx, &vulnerabilities.GetVulnerabilitySummaryTimeSeriesRequest{Filter: f})
			return err
		}},
		{"ListCveSummaries", func(s *Server, f *vulnerabilities.Filter) error {
			_, err := s.ListCveSummaries(ctx, &vulnerabilities.ListCveSummariesRequest{Filter: f})
			return err
		}},
		{"ListMeanTimeToFixTrendBySeverity", func(s *Server, f *vulnerabilities.Filter) error {
			_, err := s.ListMeanTimeToFixTrendBySeverity(ctx, &vulnerabilities.ListMeanTimeToFixTrendBySeverityRequest{Filter: f})
			return err
		}},
		{"ListWorkloadsForVulnerability", func(s *Server, f *vulnerabilities.Filter) error {
			_, err := s.ListWorkloadsForVulnerability(ctx, &vulnerabilities.ListWorkloadsForVulnerabilityRequest{Filter: f})
			return err
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call(&Server{}, &vulnerabilities.Filter{Labels: []*vulnerabilities.LabelFilter{{Key: "owner"}}})
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

func TestSummaryLabelParametersPreserveOptionalValues(t *testing.T) {
	got, err := summaryLabelParameters(&vulnerabilities.Filter{Labels: []*vulnerabilities.LabelFilter{
		{Key: "owner"}, {Key: "empty", Value: new("")},
	}})
	require.NoError(t, err)
	assert.JSONEq(t, `[{"key":"owner"},{"key":"empty","value":""}]`, string(got))
}

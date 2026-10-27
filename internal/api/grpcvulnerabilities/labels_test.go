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
				Labels: tt.filter,
			})
			assert.Nil(t, response)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

func TestSummaryLabelParametersPreserveOptionalValues(t *testing.T) {
	got, err := summaryLabelParameters([]*vulnerabilities.LabelFilter{
		{Key: "owner"}, {Key: "empty", Value: new("")},
	})
	require.NoError(t, err)
	assert.JSONEq(t, `[{"key":"owner"},{"key":"empty","value":""}]`, string(got))
}

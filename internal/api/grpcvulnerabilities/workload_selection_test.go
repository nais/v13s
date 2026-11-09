package grpcvulnerabilities

import (
	"context"
	"testing"

	"github.com/nais/v13s/internal/database/sql"
	sqlmock "github.com/nais/v13s/internal/mocks/Querier"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestWorkloadSelectionParameters(t *testing.T) {
	for _, tt := range []struct {
		name      string
		selection *vulnerabilities.WorkloadSelection
		want      string
	}{
		{name: "absent"},
		{name: "empty", selection: &vulnerabilities.WorkloadSelection{}, want: "[]"},
		{
			name:      "open type",
			selection: &vulnerabilities.WorkloadSelection{Workloads: []*vulnerabilities.WorkloadIdentity{{Cluster: "dev", Namespace: "team", Name: "app", Type: "daemonset"}}},
			want:      `[{"cluster":"dev","namespace":"team","name":"app","type":"daemonset"}]`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := workloadSelectionParameters(tt.selection)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want || (got == nil) != (tt.selection == nil) {
				t.Fatalf("parameters = %q, want %q (selection %v)", got, tt.want, tt.selection)
			}
		})
	}
}

func TestCveSelectionUsesLiveQuery(t *testing.T) {
	for _, selection := range []*vulnerabilities.WorkloadSelection{
		{},
		{Workloads: []*vulnerabilities.WorkloadIdentity{{Cluster: "dev", Namespace: "team", Name: "app", Type: "daemonset"}}},
	} {
		ctx := context.Background()
		parameters, err := workloadSelectionParameters(selection)
		if err != nil {
			t.Fatal(err)
		}
		querier := sqlmock.NewMockQuerier(t)
		querier.EXPECT().ListCveSummaries(ctx, sql.ListCveSummariesParams{
			WorkloadSelection: parameters,
			ExcludeClusters:   []string{},
			ExcludeNamespaces: []string{},
			OrderBy:           "affected_workloads_asc",
			Limit:             1,
		}).Return([]*sql.ListCveSummariesRow{}, nil).Once()
		response, err := (&Server{querier: querier}).ListCveSummaries(ctx, &vulnerabilities.ListCveSummariesRequest{
			WorkloadSelection: selection,
			Limit:             1,
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(response.GetNodes()) != 0 || response.GetPageInfo().GetTotalCount() != 0 {
			t.Fatalf("unexpected response: %v", response)
		}
	}
}

func TestSelectedSummaryEmptyPageRetainsTotal(t *testing.T) {
	ctx := context.Background()
	querier := sqlmock.NewMockQuerier(t)
	selection := &vulnerabilities.WorkloadSelection{
		Workloads: []*vulnerabilities.WorkloadIdentity{{Cluster: "dev", Namespace: "team", Name: "app", Type: "app"}},
	}
	parameters, err := workloadSelectionParameters(selection)
	if err != nil {
		t.Fatal(err)
	}
	params := sql.ListVulnerabilitySummariesParams{
		WorkloadSelection: parameters,
		OrderBy:           "critical_asc",
		Limit:             1,
		Offset:            10,
	}
	querier.EXPECT().ListVulnerabilitySummaries(ctx, params).Return([]*sql.ListVulnerabilitySummariesRow{}, nil).Once()
	params.Offset = 0
	querier.EXPECT().ListVulnerabilitySummaries(ctx, params).Return([]*sql.ListVulnerabilitySummariesRow{{TotalCount: 1}}, nil).Once()
	response, err := (&Server{querier: querier}).ListVulnerabilitySummaries(ctx, &vulnerabilities.ListVulnerabilitySummariesRequest{
		WorkloadSelection: selection,
		Limit:             1,
		Offset:            10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.GetNodes()) != 0 || response.GetPageInfo().GetTotalCount() != 1 {
		t.Fatalf("unexpected response: %v", response)
	}
}

func TestWorkloadSelectionRejectsInvalidIdentities(t *testing.T) {
	for _, tt := range []struct {
		name     string
		workload *vulnerabilities.WorkloadIdentity
	}{
		{name: "nil"},
		{name: "empty", workload: &vulnerabilities.WorkloadIdentity{}},
		{name: "missing cluster", workload: &vulnerabilities.WorkloadIdentity{Namespace: "team", Name: "app", Type: "app"}},
		{name: "missing namespace", workload: &vulnerabilities.WorkloadIdentity{Cluster: "dev", Name: "app", Type: "app"}},
		{name: "missing name", workload: &vulnerabilities.WorkloadIdentity{Cluster: "dev", Namespace: "team", Type: "app"}},
		{name: "whitespace", workload: &vulnerabilities.WorkloadIdentity{Cluster: " dev", Namespace: "team", Name: "app", Type: "app"}},
		{name: "missing type", workload: &vulnerabilities.WorkloadIdentity{Cluster: "dev", Namespace: "team", Name: "app"}},
		{name: "type whitespace", workload: &vulnerabilities.WorkloadIdentity{Cluster: "dev", Namespace: "team", Name: "app", Type: "daemonset "}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			selection := &vulnerabilities.WorkloadSelection{Workloads: []*vulnerabilities.WorkloadIdentity{tt.workload}}
			server := &Server{}
			ctx := context.Background()
			calls := map[string]func() error{
				"workload summaries": func() error {
					_, err := server.ListVulnerabilitySummaries(ctx, &vulnerabilities.ListVulnerabilitySummariesRequest{WorkloadSelection: selection})
					return err
				},
				"aggregate": func() error {
					_, err := server.GetVulnerabilitySummary(ctx, &vulnerabilities.GetVulnerabilitySummaryRequest{WorkloadSelection: selection})
					return err
				},
				"bulk aggregates": func() error {
					_, err := server.GetVulnerabilitySummaries(ctx, &vulnerabilities.GetVulnerabilitySummariesRequest{Namespaces: []string{"team"}, WorkloadSelection: selection})
					return err
				},
				"CVEs": func() error {
					_, err := server.ListCveSummaries(ctx, &vulnerabilities.ListCveSummariesRequest{WorkloadSelection: selection})
					return err
				},
				"CVE workloads": func() error {
					_, err := server.ListWorkloadsForVulnerability(ctx, &vulnerabilities.ListWorkloadsForVulnerabilityRequest{CveIds: []string{"CVE-1"}, WorkloadSelection: selection})
					return err
				},
			}
			for name, call := range calls {
				t.Run(name, func(t *testing.T) {
					if err := call(); status.Code(err) != codes.InvalidArgument {
						t.Fatalf("got %v, want InvalidArgument", err)
					}
				})
			}
		})
	}
}

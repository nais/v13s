package vulnerabilities

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestWorkloadsFilterPreservesSelectionPresence(t *testing.T) {
	for _, tt := range []struct {
		name string
		opts []Option
		want *WorkloadSelection
	}{
		{name: "absent"},
		{name: "empty", opts: []Option{WorkloadsFilter()}, want: &WorkloadSelection{}},
		{
			name: "selected",
			opts: []Option{WorkloadsFilter(&WorkloadIdentity{Cluster: "dev", Namespace: "team", Name: "app", Type: "app"})},
			want: &WorkloadSelection{Workloads: []*WorkloadIdentity{{Cluster: "dev", Namespace: "team", Name: "app", Type: "app"}}},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request := &ListVulnerabilitySummariesRequest{WorkloadSelection: GetOptions(tt.opts...).WorkloadSelection}
			encoded, err := proto.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			decoded := &ListVulnerabilitySummariesRequest{}
			if err := proto.Unmarshal(encoded, decoded); err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(decoded.GetWorkloadSelection(), tt.want) {
				t.Fatalf("selection after serialization = %v, want %v", decoded.GetWorkloadSelection(), tt.want)
			}
		})
	}
}

func TestPriorityFilterAcceptsMultiplePriorities(t *testing.T) {
	filter := GetFilter(
		PriorityFilter(Priority_PRIORITY_HIGH, Priority_PRIORITY_ELEVATED),
	)

	if len(filter.GetPriorities()) != 2 {
		t.Fatalf("expected 2 priorities, got %d", len(filter.GetPriorities()))
	}
	if filter.GetPriorities()[0] != Priority_PRIORITY_HIGH || filter.GetPriorities()[1] != Priority_PRIORITY_ELEVATED {
		t.Fatalf("unexpected priorities: %#v", filter.GetPriorities())
	}
}

func TestPriorityFilterSinglePriorityUsesExactSetField(t *testing.T) {
	filter := GetFilter(
		PriorityFilter(Priority_PRIORITY_HIGH),
	)

	if len(filter.GetPriorities()) != 1 || filter.GetPriorities()[0] != Priority_PRIORITY_HIGH {
		t.Fatalf("expected exact priority set [HIGH], got %#v", filter.GetPriorities())
	}
}

func TestKevFilterPreservesBooleanValue(t *testing.T) {
	for _, hasKev := range []bool{true, false} {
		t.Run(map[bool]string{true: "true", false: "false"}[hasKev], func(t *testing.T) {
			filter := GetFilter(KevFilter(hasKev))

			if filter.HasKev == nil {
				t.Fatal("expected has_kev to be set")
			}
			if filter.GetHasKev() != hasKev {
				t.Fatalf("expected has_kev=%t, got %t", hasKev, filter.GetHasKev())
			}
		})
	}
}

func TestSbomStatusFilterAcceptsMultipleStatuses(t *testing.T) {
	options := GetOptions(
		SbomStatusFilter(SbomStatus_SBOM_STATUS_READY, SbomStatus_SBOM_STATUS_PROCESSING),
	)

	if len(options.SbomStatuses) != 2 {
		t.Fatalf("expected 2 SBOM statuses, got %d", len(options.SbomStatuses))
	}
	if options.SbomStatuses[0] != SbomStatus_SBOM_STATUS_READY ||
		options.SbomStatuses[1] != SbomStatus_SBOM_STATUS_PROCESSING {
		t.Fatalf("unexpected SBOM statuses: %#v", options.SbomStatuses)
	}
}

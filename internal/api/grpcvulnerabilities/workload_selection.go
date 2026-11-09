package grpcvulnerabilities

import (
	"encoding/json"
	"strings"

	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func workloadSelectionParameters(selection *vulnerabilities.WorkloadSelection) ([]byte, error) {
	if selection == nil {
		return nil, nil
	}
	for _, workload := range selection.GetWorkloads() {
		if workload == nil {
			return nil, status.Error(codes.InvalidArgument, "workload identity is required")
		}
		for _, value := range []string{workload.GetCluster(), workload.GetNamespace(), workload.GetName(), workload.GetType()} {
			if value == "" || strings.TrimSpace(value) != value {
				return nil, status.Error(codes.InvalidArgument, "workload identity fields must be nonempty and must not contain surrounding whitespace")
			}
		}
	}
	if len(selection.GetWorkloads()) == 0 {
		return []byte("[]"), nil
	}
	return json.Marshal(selection.GetWorkloads())
}

func workloadTypesForSelection(filter *vulnerabilities.Filter, selection *vulnerabilities.WorkloadSelection) []string {
	if selection != nil && filter.WorkloadType == nil {
		return nil
	}
	return filter.GetWorkloadTypes()
}

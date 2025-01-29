package main

import (
	"context"
	"fmt"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"

	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	c, err := vulnerabilities.NewClient(
		"localhost:50051",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		panic(err)
	}

	workloadManagement(c)

	listVulnz(c)

	resp, err := c.ListVulnerabilitySummaries(
		context.Background(),
		vulnerabilities.ClusterFilter("prod-gcp"),
		vulnerabilities.NamespaceFilter("nais-system"),
		vulnerabilities.Limit(10),
		vulnerabilities.Offset(0),
	)

	handle(resp, err)

	//resp3, err := c.ListVulnerabilities(
	//	context.Background(),
	//	vulnerabilities.ClusterFilter("prod-gcp"),
	//	vulnerabilities.NamespaceFilter("nais-system"),
	//	vulnerabilities.WorkloadTypeFilter("job"),
	//	vulnerabilities.Limit(10),
	//	vulnerabilities.Suppressed(),
	//)
	//if err != nil {
	//	panic(err)
	//}
	//
	//fmt.Printf("Filters: %v\n", resp3.Filter)
	//for _, v := range resp3.Workloads {
	//	fmt.Printf("workload: %v\n", v.Workload)
	//	fmt.Printf("vulnerabilities: %v\n", v.Vulnerabilities)
	//}

	resp2, err := c.GetVulnerabilitySummary(
		context.Background(),
		vulnerabilities.ClusterFilter("prod-gcp"),
		vulnerabilities.NamespaceFilter("nais-system"),
		vulnerabilities.WorkloadFilter("pull-metrics"),
	)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Filters: %v\n", resp2.Filter)
	fmt.Printf("summary: %v\n", resp2.VulnerabilitySummary)
}

func listVulnz(c vulnerabilities.Client) {
	resp, err := c.ListVulnerabilities(
		context.Background(),
		vulnerabilities.ClusterFilter("dev-gcp"),
		vulnerabilities.Suppressed(),
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("number of vulnerabilities: %v\n", len(resp.Workloads))
	for _, w := range resp.Workloads {
		fmt.Printf("workload: %v\n", w.Workload)
		//fmt.Printf("vulnerabilities: %v\n", w.Vulnerabilities)
	}
}

func workloadManagement(c vulnerabilities.Client) {
	ctx := context.Background()
	_, err := c.RegisterWorkload(
		ctx,
		&management.RegisterWorkloadRequest{
			Cluster:      "management",
			Namespace:    "nais-system",
			Workload:     "console-frontend",
			WorkloadType: "app",
			ImageName:    "europe-north1-docker.pkg.dev/nais-io/nais/images/console-frontend",
			ImageTag:     "2025-01-28-122116-2ade48c",
			Metadata: &management.Metadata{
				Labels: map[string]string{
					"workflow": "deploy",
				},
			},
		},
	)
	if err != nil {
		panic(err)
	}
	_, err = c.RegisterWorkload(
		ctx,
		&management.RegisterWorkloadRequest{
			Cluster:      "dev-gcp",
			Namespace:    "nais-system",
			Workload:     "debug",
			WorkloadType: "app",
			ImageName:    "europe-north1-docker.pkg.dev/nais-io/nais/images/testapp",
			ImageTag:     "latest",
			Metadata: &management.Metadata{
				Labels: map[string]string{
					"workflow": "deploy",
				},
			},
		},
	)
	if err != nil {
		panic(err)
	}

}

func handle(resp *vulnerabilities.ListVulnerabilitySummariesResponse, err error) {
	if err != nil {
		panic(err)
	}
	for _, w := range resp.WorkloadSummaries {
		fmt.Printf("workload: %v\n", w.Workload)
		fmt.Printf("summary: %v\n", w.VulnerabilitySummary)
	}
}

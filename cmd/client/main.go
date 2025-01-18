package main

import (
	"context"
	"fmt"
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

	resp, err := c.ListVulnerabilitySummaries(
		context.Background(),
		vulnerabilities.ClusterFilter("prod-gcp"),
		vulnerabilities.NamespaceFilter("nais-system"),
	)

	handle(resp, err)

	resp2, err := c.GetVulnerabilitySummaryResponse(
		context.Background(),
		vulnerabilities.ClusterFilter("prod-gcp"),
		vulnerabilities.NamespaceFilter("nais-system"),
	)

	if err != nil {
		panic(err)
	}

	fmt.Printf("workload: %v\n", resp2.Filter)
	fmt.Printf("summary: %v\n", resp2.VulnerabilitySummary)

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

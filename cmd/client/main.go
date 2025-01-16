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

	resp, err := c.ListVulnerabilitySummaries(context.Background())
	handle(resp, err)

	resp, err = c.ListVulnerabilitySummaries(
		context.Background(),
		vulnerabilities.ClusterFilter("cluster1"),
		vulnerabilities.NamespaceFilter("namespace1"),
	)
	handle(resp, err)
}

func handle(resp *vulnerabilities.ListWorkloadSummariesResponse, err error) {
	if err != nil {
		panic(err)
	}
	for _, w := range resp.WorkloadSummaries {
		fmt.Printf("workload: %v\n", w.Workload)
		fmt.Printf("summary: %v\n", w.VulnerabilitySummary)
	}
}

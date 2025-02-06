package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/nais/v13s/pkg/api/auth"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"strings"
)

func main() {
	//url := "vulnerabilities.dev-nais.cloud.nais.io"
	url := "localhost:50051"
	ctx := context.Background()

	dialOptions := make([]grpc.DialOption, 0)
	if strings.Contains(url, "localhost") {
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		// TODO: G402 (CWE-295): TLS MinVersion too low. (Confidence: HIGH, Severity: HIGH)
		tlsOpts := &tls.Config{}
		cred := credentials.NewTLS(tlsOpts)
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(cred))
	}
	creds, err := auth.PerRPCGoogleIDToken(ctx, "v13s-sa@nais-management-7178.iam.gserviceaccount.com", "vulnz")
	if err != nil {
		log.Fatalf("%v", err)
	}
	dialOptions = append(dialOptions, grpc.WithPerRPCCredentials(creds))

	c, err := vulnerabilities.NewClient(
		url,
		dialOptions...,
	)
	if err != nil {
		panic(err)
	}

	defer c.Close()

	listVulnz(c)
	//workloadManagement(c)
	/*
		listVulnz(c)

		resp, err := c.ListVulnerabilitySummaries(
			context.Background(),
			vulnerabilities.ClusterFilter("prod-gcp"),
			vulnerabilities.NamespaceFilter("nais-system"),
			vulnerabilities.Limit(10),
			vulnerabilities.Offset(0),
		)

		handle(resp, err)

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
	*/
}

func listVulnz(c vulnerabilities.Client) {
	resp, err := c.ListVulnerabilities(
		context.Background(),
		//vulnerabilities.ClusterFilter("dev-gcp"),
		vulnerabilities.Suppressed(),
	)
	if err != nil {
		panic(err)
	}

	fmt.Printf("number of vulnerabilities: %v\n", len(resp.Nodes))
	for _, w := range resp.Nodes {
		fmt.Printf("workload: %v\n", w.WorkloadRef)
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

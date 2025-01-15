package main

import (
	"context"
	"fmt"
	"github.com/nais/v13s/pkg/client/proto/vulnerabilities"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"log"
)

func main() {

	vulnzClient, err := NewVulnzClient("localhost:50051")
	if err != nil {
		log.Fatalf("Failed to create client: %v\n", err)
	}

	vulnzClient.listWorkloadSummaries()
	//vulnzClient.getWorkloadSummary()
	//vulnzClient.listVulnerabilities()
}

func NewVulnzClient(target string) (*VulnzClient, error) {
	clientConn, err := NewGrpcClient(target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	return &VulnzClient{vulnerabilities.NewVulnerabilitiesClient(clientConn)}, nil
}

func (c *VulnzClient) listVulnerabilities() {
	cluster := "cluster1"
	namespace := "namespace1"
	name := "workload1"
	wType := "Deployment"

	resp, err := c.ListVulnerabilities(context.Background(), &vulnerabilities.ListVulnerabilitiesRequest{
		Filter: &vulnerabilities.Filter{
			Cluster:      &cluster,
			Namespace:    &namespace,
			Workload:     &name,
			WorkloadType: &wType,
		},
	})
	if err != nil {
		panic(err)
	}
	for _, v := range resp.Workloads {
		println(v.Name)
		println(v.Type)
		println(v.Cluster)
		println(v.Namespace)
		for _, vuln := range v.Vulnerabilities {
			println(vuln.Package)
			println(vuln.Cwe.Severity)
		}
	}

}

func (c *VulnzClient) getWorkloadSummary() {
	// get a summary for a specific workload
	cluster := "cluster1"
	namespace := "namespace1"
	name := "workload1"
	wType := "Deployment"

	resp, err := c.GetSummary(context.Background(), &vulnerabilities.GetSummaryRequest{
		Filter: &vulnerabilities.Filter{
			Cluster:      &cluster,
			Namespace:    &namespace,
			Workload:     &name,
			WorkloadType: &wType,
		},
	})
	if err != nil {
		panic(err)
	}

	println(resp.VulnerabilitySummary.Critical)
}

func (c *VulnzClient) listWorkloadSummaries() {
	cluster := "cluster1"
	namespace := "namespace1"

	// get summaries for all workloads in the namespace
	resp := c.ListWorkloads(&cluster, &namespace, nil, nil)
	for _, s := range resp.WorkloadSummaries {
		println(*s.Cluster)
		println(s.Name)
		println(s.VulnerabilitySummary.Critical)
	}

	// get summaries for all workloads in the cluster
	resp = c.ListWorkloads(&cluster, nil, nil, nil)
	for _, s := range resp.WorkloadSummaries {
		println(*s.Cluster)
		println(s.Name)
		println(s.VulnerabilitySummary.Critical)
	}

	// get summaries for all workloads across all clusters
	resp = c.ListWorkloads(nil, nil, nil, nil)
	for _, s := range resp.WorkloadSummaries {
		println(*s.Cluster)
		println(s.Name)
		println(s.VulnerabilitySummary.Critical)
	}
}

type VulnzClient struct {
	vulnerabilities.VulnerabilitiesClient
}

func (c *VulnzClient) ListWorkloads(cluster, namespace, name, wType *string) *vulnerabilities.ListWorkloadSummariesResponse {
	r, err := c.ListWorkloadSummaries(context.Background(), &vulnerabilities.ListWorkloadSummariesRequest{
		Filter: &vulnerabilities.Filter{
			Cluster:      cluster,
			Namespace:    namespace,
			Workload:     name,
			WorkloadType: wType,
		},
	})
	if err != nil {
		panic(err)
	}
	return r
}

type GrpcClient struct {
	conn *grpc.ClientConn
}

func NewGrpcClient(target string, opts ...grpc.DialOption) (*GrpcClient, error) {
	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gRPC server: %w", err)
	}
	return &GrpcClient{conn: conn}, nil
}

// Invoke implements the unary RPC call.
func (v GrpcClient) Invoke(ctx context.Context, method string, args any, reply any, opts ...grpc.CallOption) error {
	if v.conn == nil {
		return fmt.Errorf("gRPC connection is not initialized")
	}
	return v.conn.Invoke(ctx, method, args, reply, opts...)
}

// NewStream implements the streaming RPC call.
func (v GrpcClient) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	if v.conn == nil {
		return nil, fmt.Errorf("gRPC connection is not initialized")
	}
	return v.conn.NewStream(ctx, desc, method, opts...)
}

var _ grpc.ClientConnInterface = &GrpcClient{}

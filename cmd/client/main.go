package main

import (
	context "context"
	"github.com/nais/v13s/pkg/client/proto/vulnerabilities"
	"google.golang.org/grpc"
)

func main() {
	listWorkloadSummaries()
	getWorkloadSummary()
	listVulnerabilities()
}

func listVulnerabilities() {
	c := &VulnzClient{vulnerabilities.NewVulnerabilitiesClient(GrpcClient{})}
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

func getWorkloadSummary() {
	// get a summary for a specific workload
	c := &VulnzClient{vulnerabilities.NewVulnerabilitiesClient(GrpcClient{})}
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

func listWorkloadSummaries() {
	c := &VulnzClient{vulnerabilities.NewVulnerabilitiesClient(GrpcClient{})}
	cluster := "cluster1"
	namespace := "namespace1"

	// get summaries for all workloads in the namespace
	resp := c.ListWorkloads(&cluster, &namespace, nil, nil)
	for _, s := range resp.WorkloadSummaries {
		println(s.Cluster)
		println(s.Name)
		println(s.VulnerabilitySummary.Critical)
	}

	// get summaries for all workloads in the cluster
	resp = c.ListWorkloads(&cluster, nil, nil, nil)
	for _, s := range resp.WorkloadSummaries {
		println(s.Cluster)
		println(s.Name)
		println(s.VulnerabilitySummary.Critical)
	}

	// get summaries for all workloads across all clusters
	resp = c.ListWorkloads(nil, nil, nil, nil)
	for _, s := range resp.WorkloadSummaries {
		println(s.Cluster)
		println(s.Name)
		println(s.VulnerabilitySummary.Critical)
	}
}

type VulnzClient struct {
	vulnerabilities.VulnerabilitiesClient
}

func (v VulnzClient) ListWorkloads(cluster, namespace, name, wType *string) *vulnerabilities.ListWorkloadSummariesResponse {
	r, err := v.ListWorkloadSummaries(context.Background(), &vulnerabilities.ListWorkloadSummariesRequest{
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
}

func (v GrpcClient) Invoke(ctx context.Context, method string, args any, reply any, opts ...grpc.CallOption) error {
	//TODO implement me
	panic("implement me")
}

func (v GrpcClient) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	//TODO implement me
	panic("implement me")
}

var _ grpc.ClientConnInterface = &GrpcClient{}

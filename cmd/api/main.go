package main

import (
	"context"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"google.golang.org/grpc"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

type Server struct {
	vulnerabilities.UnimplementedVulnerabilitiesServer
}

// ListVulnerabilitySummaries implements the ListVulnerabilitySummaries RPC
func (s *Server) ListVulnerabilitySummaries(ctx context.Context, req *vulnerabilities.ListWorkloadSummariesRequest) (*vulnerabilities.ListWorkloadSummariesResponse, error) {
	log.Printf("Received ListVulnerabilitySummaries request: %v", req)
	cluster := "cluster-1"
	namespace := "namespace-1"
	allWorkloads := []*vulnerabilities.WorkloadSummary{
		{
			Workload: &vulnerabilities.Workload{
				Cluster:   cluster,
				Namespace: namespace,
				Name:      "wName",
				Type:      "deploy",
				Image:     "image1:tag1",
			},
			VulnerabilitySummary: &vulnerabilities.Summary{Critical: 5, High: 10, Medium: 20, Low: 15},
		},
	}

	response := &vulnerabilities.ListWorkloadSummariesResponse{
		WorkloadSummaries: allWorkloads,
	}
	log.Printf("Responding with: %v", response)
	return response, nil
}

func main() {
	listener, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	vulnerabilities.RegisterVulnerabilitiesServer(grpcServer, &Server{})

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Println("gRPC server is running on port 50051...")
		if err := grpcServer.Serve(listener); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	<-stop
	log.Println("Shutting down gRPC server...")
	grpcServer.GracefulStop()
}

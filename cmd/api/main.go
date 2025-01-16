package main

import (
	"github.com/nais/v13s/internal/server"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"google.golang.org/grpc"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	listener, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	vulnerabilities.RegisterVulnerabilitiesServer(grpcServer, &server.Server{})

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

package main

import (
	"fmt"
	"github.com/joho/godotenv"
	"github.com/nais/v13s/internal/dependencytrack"
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
	err := godotenv.Load()
	if err != nil {
		fmt.Println("No .env file found")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:50051")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	dpClient, err := dependencytrack.NewClient(
		os.Getenv("V13S_DEPENDENCYTRACK_API_KEY"),
		os.Getenv("V13S_DEPENDENCYTRACK_URL"),
	)
	if err != nil {
		log.Fatalf("Failed to create DependencyTrack client: %v", err)
	}

	vulnerabilities.RegisterVulnerabilitiesServer(grpcServer, &server.Server{DpClient: dpClient})

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

package main

import (
	"context"
	"fmt"
	"github.com/nais/v13s/internal/database/sql"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/nais/v13s/internal/database"
	log "github.com/sirupsen/logrus"

	"github.com/joho/godotenv"
	"github.com/nais/v13s/internal/dependencytrack"
	"github.com/nais/v13s/internal/server"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"google.golang.org/grpc"
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

	ctx := context.Background()
	log.Infof("initializing database")

	// TODO: fix env stuff, use transactions etc. look at nais api
	pool, err := database.New(ctx, "postgres://v13s:v13s@127.0.0.1:3002/v13s?sslmode=disable", log.WithField("component", "database"))
	if err != nil {
		log.Fatalf("Failed to create database pool: %v", err)
	}
	defer pool.Close()
	db := sql.New(pool)

	grpcServer := grpc.NewServer()
	dpClient, err := dependencytrack.NewClient(
		os.Getenv("V13S_DEPENDENCYTRACK_API_KEY"),
		os.Getenv("V13S_DEPENDENCYTRACK_URL"),
	)
	if err != nil {
		log.Fatalf("Failed to create DependencyTrack client: %v", err)
	}

	vulnerabilities.RegisterVulnerabilitiesServer(grpcServer, &server.Server{DpClient: dpClient, Db: db})

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	<-stop
	grpcServer.GracefulStop()
}

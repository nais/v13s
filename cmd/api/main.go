package main

import (
	"context"
	"fmt"
	"github.com/nais/v13s/internal/api/grpcmgmt"
	"github.com/nais/v13s/internal/api/grpcvulnerabilities"
	"github.com/nais/v13s/internal/updater"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nais/v13s/internal/database/sql"

	"github.com/nais/v13s/internal/database"
	log "github.com/sirupsen/logrus"

	"github.com/joho/godotenv"
	"github.com/nais/v13s/internal/dependencytrack"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"google.golang.org/grpc"
)

const (
	listenAddr = "127.0.0.1:50051"
)

// handle env vars better
func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("No .env file found")
	}

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Info("Initializing database")

	dbURL := os.Getenv("V13S_DATABASE_URL")
	if dbURL == "" {
		log.Fatal("Database URL is not set")
	}

	pool, err := database.New(ctx, dbURL, log.WithField("component", "database"))
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

	u := updater.NewUpdater(db, dpClient, 60*time.Minute)
	vulnerabilities.RegisterVulnerabilitiesServer(grpcServer, grpcvulnerabilities.NewServer(db))
	management.RegisterManagementServer(grpcServer, grpcmgmt.NewServer(db, u))

	go func() {
		if err := u.Run(ctx); err != nil {
			log.Fatalf("Updater failed: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	srvErr := make(chan error, 1)
	go func() {
		srvErr <- grpcServer.Serve(listener)
	}()

	select {
	case <-stop:
		log.Info("Shutting down gracefully")
	case err := <-srvErr:
		log.Fatalf("GRPC Server Error: %v", err)
	}

	grpcServer.GracefulStop()
}

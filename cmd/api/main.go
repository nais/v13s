package main

import (
	"context"
	"fmt"
	"github.com/nais/v13s/internal/api/grpcmgmt"
	"github.com/nais/v13s/internal/api/grpcvulnerabilities"
	"github.com/nais/v13s/internal/updater"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"
	"google.golang.org/grpc/grpclog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nais/v13s/internal/database/sql"

	"github.com/nais/v13s/internal/database"
	log "github.com/sirupsen/logrus"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"github.com/nais/v13s/internal/dependencytrack"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"google.golang.org/grpc"
)

type config struct {
	ListenAddr            string        `envonfig:"LISTEN_ADDR" default:"0.0.0.0:50051"`
	DependencytrackUrl    string        `envconfig:"DEPENDENCYTRACK_URL" required:"true"`
	DependencytrackApiKey string        `envconfig:"DEPENDENCYTRACK_API_KEY" required:"true"`
	DatabaseUrl           string        `envconfig:"DATABASE_URL" required:"true"`
	UpdateInterval        time.Duration `envconfig:"UPDATE_INTERVAL" default:"1m"`
}

// handle env vars better
func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("No .env file found")
	}

	var c config
	err = envconfig.Process("V13S", &c)
	if err != nil {
		log.Fatal(err.Error())
	}

	grpclog.SetLoggerV2(grpclog.NewLoggerV2(os.Stdout, os.Stdout, os.Stderr))

	listener, err := net.Listen("tcp", c.ListenAddr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Info("Initializing database")

	pool, err := database.New(ctx, c.DatabaseUrl, log.WithField("component", "database"))
	if err != nil {
		log.Fatalf("Failed to create database pool: %v", err)
	}
	defer pool.Close()

	db := sql.New(pool)

	grpcServer := grpc.NewServer()
	dpClient, err := dependencytrack.NewClient(
		c.DependencytrackUrl,
		c.DependencytrackApiKey,
	)
	if err != nil {
		log.Fatalf("Failed to create DependencyTrack client: %v", err)
	}

	u := updater.NewUpdater(db, dpClient, c.UpdateInterval)
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

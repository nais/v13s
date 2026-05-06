package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"github.com/nais/v13s/internal/config"
	"github.com/nais/v13s/internal/database"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources/osv"
	"github.com/sirupsen/logrus"
)

func main() {
	log := logrus.New()
	log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	log.SetLevel(logrus.DebugLevel)

	if err := godotenv.Load(); err != nil {
		log.Info("no .env file found, reading from environment")
	}

	cfg := &struct {
		DatabaseURL string `envconfig:"DATABASE_URL" required:"true"`
		Osv         config.OsvConfig
	}{}
	if err := envconfig.Process("", cfg); err != nil {
		log.WithError(err).Fatal("failed to process config")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := database.NewPool(ctx, cfg.DatabaseURL, log, false)
	if err != nil {
		log.WithError(err).Fatal("failed to connect to database")
	}
	defer pool.Close()

	querier := sql.New(pool)
	fetcher := osv.NewFetcherWithClient(
		osv.NewClientWithURL(cfg.Osv.BaseURL),
		querier,
		logrus.NewEntry(log),
	)

	log.Infof("syncing OSV fix versions from %s", cfg.Osv.BaseURL)
	if err := fetcher.Sync(ctx); err != nil {
		log.WithError(err).Fatal("OSV sync failed")
	}

	log.Info("OSV sync complete")
}

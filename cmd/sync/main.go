package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"github.com/nais/v13s/internal/config"
	"github.com/nais/v13s/internal/database"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources/kev"
	"github.com/nais/v13s/internal/sources/osv"
	"github.com/sirupsen/logrus"
)

type syncer interface {
	Sync(ctx context.Context) error
}

type source struct {
	name        string
	description string
	newSyncer   func(cfg *envConfig, pool *pgxpool.Pool, log *logrus.Logger) syncer
}

type envConfig struct {
	DatabaseURL string `envconfig:"DATABASE_URL" required:"true"`
	Kev         config.KevConfig
	Osv         config.OsvConfig
}

type prioritySyncer struct {
	querier sql.Querier
	log     *logrus.Entry
}

func (p prioritySyncer) Sync(ctx context.Context) error {
	p.log.Info("recomputing CVE priorities from severity, EPSS and KEV data")
	updated, err := p.querier.UpdateCvePriority(ctx)
	if err != nil {
		return fmt.Errorf("updating cve priority: %w", err)
	}
	p.log.WithField("rows", updated).Info("cve priorities recomputed")
	return nil
}

var sources = []source{
	{
		name:        "kev",
		description: "sync the CISA KEV catalog",
		newSyncer: func(cfg *envConfig, pool *pgxpool.Pool, log *logrus.Logger) syncer {
			return kev.NewFetcherWithClient(
				kev.NewClientWithURL(cfg.Kev.CatalogURL),
				sql.New(pool),
				logrus.NewEntry(log),
			)
		},
	},
	{
		name:        "osv",
		description: "sync OSV fix versions",
		newSyncer: func(cfg *envConfig, pool *pgxpool.Pool, log *logrus.Logger) syncer {
			return osv.NewFetcherWithClient(
				osv.NewClientWithURL(cfg.Osv.BaseURL),
				pool,
				logrus.NewEntry(log),
			)
		},
	},
	{
		name:        "priority",
		description: "recompute CVE priorities from data already in the database",
		newSyncer: func(cfg *envConfig, pool *pgxpool.Pool, log *logrus.Logger) syncer {
			return prioritySyncer{
				querier: sql.New(pool),
				log:     logrus.NewEntry(log),
			}
		},
	},
}

func lookupSource(name string) (source, bool) {
	for _, s := range sources {
		if s.name == name {
			return s, true
		}
	}
	return source{}, false
}

func usage() string {
	var out strings.Builder
	out.WriteString("usage: sync <source>\n\nsources:\n")
	for _, s := range sources {
		out.WriteString(fmt.Sprintf("  %-8s %s\n", s.name, s.description))
	}
	return out.String()
}

func main() {
	log := logrus.New()
	log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	log.SetLevel(logrus.DebugLevel)

	if len(os.Args) != 2 {
		fmt.Fprint(os.Stderr, usage())
		os.Exit(2)
	}

	src, ok := lookupSource(os.Args[1])
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown source %q\n\n%s", os.Args[1], usage())
		os.Exit(2)
	}

	if err := godotenv.Load(); err != nil {
		log.Info("no .env file found, reading from environment")
	}

	cfg := &envConfig{}
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

	fetcher := src.newSyncer(cfg, pool, log)

	log.Infof("running %s sync", src.name)
	if err := fetcher.Sync(ctx); err != nil {
		log.WithError(err).Fatalf("%s sync failed", src.name)
	}

	log.Infof("%s sync complete", src.name)
}

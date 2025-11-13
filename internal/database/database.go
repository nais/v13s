package database

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"regexp"
	"time"

	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/sirupsen/logrus"
)

//go:embed migrations/0*.sql
var embedMigrations embed.FS

const (
	maxRetries    = 6
	retryBaseWait = 5 * time.Second
)

var regParseSQLName = regexp.MustCompile(`\-\-\s*name:\s+(\S+)`)

func New(ctx context.Context, dsn string, log logrus.FieldLogger) (*pgxpool.Pool, error) {
	conn, err := NewPool(ctx, dsn, log, true)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to the database: %w", err)
	}
	return conn, nil
}

func NewPool(ctx context.Context, dsn string, log logrus.FieldLogger, migrate bool) (*pgxpool.Pool, error) {
	if migrate {
		var migErr error
		for i := 0; i < maxRetries; i++ {
			migErr = migrateDatabaseSchema("pgx", dsn, log)
			if migErr == nil {
				break
			}

			wait := retryBaseWait * time.Duration(i+1)
			if i+1 == maxRetries {
				log.WithError(migErr).Errorf("Database migration failed after %d attempts", maxRetries)
			} else {
				log.Warnf("Database migration retry %d/%d; waiting %s...",
					i+1, maxRetries, wait)
			}

			time.Sleep(wait)
		}
		if migErr != nil {
			return nil, fmt.Errorf("migration failed after %d attempts: %w", maxRetries, migErr)
		}
	}

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dsn config: %w", err)
	}
	config.MaxConns = 25
	config.ConnConfig.Tracer = otelpgx.NewTracer(
		otelpgx.WithTrimSQLInSpanName(),
		otelpgx.WithSpanNameFunc(func(stmt string) string {
			matches := regParseSQLName.FindStringSubmatch(stmt)
			if len(matches) > 1 {
				return matches[1]
			}

			return "unknown"
		}),
	)

	config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		for _, typ := range []string{"image_state", "_image_state"} {
			t, err := conn.LoadType(ctx, typ)
			if err != nil {
				return fmt.Errorf("failed to load type %s: %w", typ, err)
			}
			conn.TypeMap().RegisterType(t)
		}
		return nil
	}

	var pool *pgxpool.Pool
	var pingErr error
	for i := 0; i < maxRetries; i++ {
		pool, err = pgxpool.NewWithConfig(ctx, config)
		if err == nil {
			if pingErr = pool.Ping(ctx); pingErr == nil {
				log.Infof("connected to database on attempt %d of max retry %d", i+1, maxRetries)
				return pool, nil
			}
			err = pingErr
		}

		wait := retryBaseWait * time.Duration(i+1)
		if i+1 == maxRetries {
			log.WithError(err).Errorf("Database connection failed after %d attempts", maxRetries)
		} else {
			log.Warnf("Database connection retry %d/%d; waiting %s...",
				i+1, maxRetries, wait)
		}

		time.Sleep(wait)
	}

	return nil, fmt.Errorf("giving up after %d attempts: %w", maxRetries, err)
}

// migrateDatabaseSchema runs database migrations
func migrateDatabaseSchema(driver, dsn string, log logrus.FieldLogger) error {
	goose.SetBaseFS(embedMigrations)
	goose.SetLogger(log)

	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}

	db, err := goose.OpenDBWithDriver(driver, dsn)
	if err != nil {
		return err
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.WithError(err).Error("closing database migration connection")
		}
	}()

	migrated, err := isMigrated(db, "migrations")
	if err != nil {
		return err
	}
	if migrated {
		log.Info("database already migrated; skipping")
		return nil
	}
	return goose.Up(db, "migrations")
}

func isMigrated(db *sql.DB, migrationsDir string) (bool, error) {
	migrations, err := goose.CollectMigrations(migrationsDir, 0, goose.MaxVersion)
	if err != nil {
		return false, err
	}
	if len(migrations) == 0 {
		return true, nil
	}

	lastMigration := migrations[len(migrations)-1]
	ver, err := goose.EnsureDBVersion(db)
	if err != nil {
		return false, err
	}
	return lastMigration.Version == ver, nil
}

package database

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/nais/v13s/internal/leaderelection"
	"github.com/pressly/goose/v3"
	"github.com/sirupsen/logrus"
)

//go:embed migrations/0*.sql
var embedMigrations embed.FS

const databaseConnectRetries = 5

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
		if err := migrateDatabaseSchema(ctx, "pgx", dsn, log); err != nil {
			return nil, err
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
		t, err := conn.LoadType(ctx, "image_state") // image_state type
		if err != nil {
			return fmt.Errorf("failed to load type: %w", err)
		}
		conn.TypeMap().RegisterType(t)

		t, err = conn.LoadType(ctx, "_image_state") // array of slug type
		if err != nil {
			return fmt.Errorf("failed to load type: %w", err)
		}
		conn.TypeMap().RegisterType(t)
		return nil
	}

	conn, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	connected := false
	for i := 0; i < databaseConnectRetries; i++ {
		if err = conn.Ping(ctx); err == nil {
			connected = true
			break
		}

		time.Sleep(time.Second * time.Duration(i+1))
	}

	if !connected {
		return nil, fmt.Errorf("giving up connecting to the database after %d attempts: %w", databaseConnectRetries, err)
	}

	return conn, nil
}

// migrateDatabaseSchema runs database migrations
func migrateDatabaseSchema(ctx context.Context, driver, dsn string, log logrus.FieldLogger) error {
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

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(1 * time.Second):
			if !leaderelection.IsReady() {
				continue
			}
			if !leaderelection.IsLeader() {
				migrated, err := isMigrated(db, "migrations")
				if err != nil {
					return err
				}
				log.WithField("migrated", migrated).Debug("checking database migrated")
				if !migrated {
					continue
				}
			}
			return goose.Up(db, "migrations")
		}
	}
}

func isMigrated(db *sql.DB, migrationsDir string) (bool, error) {
	migrations, err := goose.CollectMigrations(migrationsDir, 0, goose.MaxVersion)
	if err != nil {
		return false, err
	}

	var currentVersion int64
	err = db.QueryRow("SELECT version_id FROM goose_db_version ORDER BY id DESC LIMIT 1").Scan(&currentVersion)
	if errors.Is(err, sql.ErrNoRows) {
		currentVersion = 0
	} else if err != nil {
		return false, err
	}

	if len(migrations) == 0 {
		return true, nil
	}

	lastMigration := migrations[len(migrations)-1]
	return lastMigration.Version == currentVersion, nil
}

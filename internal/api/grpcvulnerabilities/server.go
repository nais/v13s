package grpcvulnerabilities

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sirupsen/logrus"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
)

var _ vulnerabilities.VulnerabilitiesServer = (*Server)(nil)

type Server struct {
	vulnerabilities.UnimplementedVulnerabilitiesServer
	querier      sql.Querier
	log          logrus.FieldLogger
	readSnapshot func(context.Context, func(context.Context, sql.Querier) error) error
}

func NewServer(pool *pgxpool.Pool, field *logrus.Entry) *Server {
	return &Server{
		querier: sql.New(pool),
		log:     field,
		readSnapshot: func(ctx context.Context, read func(context.Context, sql.Querier) error) error {
			ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			return pgx.BeginTxFunc(ctx, pool, pgx.TxOptions{
				IsoLevel:   pgx.RepeatableRead,
				AccessMode: pgx.ReadOnly,
			}, func(tx pgx.Tx) error {
				return read(ctx, sql.New(tx))
			})
		},
	}
}

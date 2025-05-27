package grpcvulnerabilities

import (
	"github.com/nais/v13s/pkg/api/vulnerabilitiespb"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/sirupsen/logrus"
)

var _ vulnerabilitiespb.VulnerabilitiesServer = (*Server)(nil)

type Server struct {
	vulnerabilitiespb.UnimplementedVulnerabilitiesServer
	querier sql.Querier
	log     logrus.FieldLogger
}

func NewServer(pool *pgxpool.Pool, field *logrus.Entry) *Server {
	return &Server{
		querier: sql.New(pool),
		log:     field,
	}
}

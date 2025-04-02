package grpcvulnerabilities

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sirupsen/logrus"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
)

var _ vulnerabilities.VulnerabilitiesServer = (*Server)(nil)

type Server struct {
	vulnerabilities.UnimplementedVulnerabilitiesServer
	querier sql.Querier
	log     logrus.FieldLogger
}

func NewServer(pool *pgxpool.Pool, field *logrus.Entry) *Server {
	return &Server{
		querier: sql.New(pool),
		log:     field,
	}
}

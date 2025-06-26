package grpcvulnerabilities

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/sirupsen/logrus"
)

var _ vulnerabilities.VulnerabilitiesServer = (*Server)(nil)

type Server struct {
	vulnerabilities.UnimplementedVulnerabilitiesServer
	querier sql.Querier
	log     logrus.FieldLogger
	source  sources.Source
}

func NewServer(pool *pgxpool.Pool, source sources.Source, field *logrus.Entry) *Server {
	return &Server{
		querier: sql.New(pool),
		source:  source,
		log:     field,
	}
}

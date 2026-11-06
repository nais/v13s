package osv

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type persistDB struct {
	sql.DBTX
	results []int64
	calls   int
	failAt  int
}

func (db *persistDB) Exec(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	db.calls++
	if db.calls == db.failAt {
		return pgconn.CommandTag{}, &pgconn.PgError{Code: "40P01"}
	}
	n := db.results[0]
	db.results = db.results[1:]
	return pgconn.NewCommandTag(fmt.Sprintf("UPDATE %d", n)), nil
}

func TestPersistDrainsFindingBatches(t *testing.T) {
	for _, fix := range []string{"1.2.3", ""} {
		t.Run("fix="+fix, func(t *testing.T) {
			db := &persistDB{results: []int64{1000, 1000, 3}}
			f := &Fetcher{log: logrus.NewEntry(logrus.New())}
			require.NoError(t, f.persist(t.Context(), sql.New(db), []fixResult{
				{cveID: "CVE-2026-1234", pkg: "pkg:npm/example@1.0.0", fixVersion: fix},
			}))
			require.Equal(t, 3, db.calls)
			require.Empty(t, db.results)
		})
	}
}

func TestPersistReturnsDeadlockWithoutRetrying(t *testing.T) {
	for _, fix := range []string{"1.2.3", ""} {
		t.Run("fix="+fix, func(t *testing.T) {
			db := &persistDB{results: []int64{1000, 3}, failAt: 2}
			f := &Fetcher{log: logrus.NewEntry(logrus.New())}
			err := f.persist(t.Context(), sql.New(db), []fixResult{
				{cveID: "CVE-2026-1234", pkg: "pkg:npm/example@1.0.0", fixVersion: fix},
			})
			var pgErr *pgconn.PgError
			require.ErrorAs(t, err, &pgErr)
			require.Equal(t, "40P01", pgErr.Code)
			require.Equal(t, 2, db.calls)
			require.Equal(t, []int64{3}, db.results)
		})
	}
}

package updater

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/job"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

const KindRefreshVulnSummaryDaily = "refresh_vuln_summary_daily"

type RefreshVulnSummaryDailyJob struct{}

func (RefreshVulnSummaryDailyJob) Kind() string { return KindRefreshVulnSummaryDaily }

func (RefreshVulnSummaryDailyJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       KindRefreshVulnSummaryDaily,
		MaxAttempts: 3,
		UniqueOpts:  river.UniqueOpts{ByArgs: true, ByPeriod: 30 * time.Minute},
	}
}

type RefreshVulnSummaryDailyWorker struct {
	db        sql.Querier
	log       logrus.FieldLogger
	jobClient job.Client
	river.WorkerDefaults[RefreshVulnSummaryDailyJob]
}

func (w *RefreshVulnSummaryDailyWorker) Work(ctx context.Context, job *river.Job[RefreshVulnSummaryDailyJob]) error {
	now := time.Now()

	lastSnapshot, err := w.db.GetLastSnapshotDateForVulnerabilitySummary(ctx)
	if err != nil {
		w.log.WithError(err).Error("could not get last snapshot date")
		return err
	}

	startDate := lastSnapshot.Time.AddDate(0, 0, 1)
	today := time.Now().Truncate(24 * time.Hour)

	for d := startDate; !d.After(today); d = d.AddDate(0, 0, 1) {
		if err := w.db.RefreshVulnerabilitySummaryForDate(ctx, pgtype.Date{Time: d, Valid: true}); err != nil {
			w.log.WithError(err).Errorf("failed to refresh summary for %s", d.Format("2006-01-02"))
		}
	}

	if err := w.db.RefreshVulnerabilitySummaryDailyView(ctx); err != nil {
		w.log.WithError(err).Error("failed to refresh vulnerability summary daily view")
		return err
	}

	w.log.Infof("vulnerability summary refreshed in %fs", time.Since(now).Seconds())
	return nil
}

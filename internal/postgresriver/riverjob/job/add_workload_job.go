package job

import (
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/model"
	"github.com/nais/v13s/internal/postgresriver/riverjob"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

const (
	KindAddWorkload = "add_workload"
)

type AddWorkloadJob struct {
	Workload *model.Workload
}

func (AddWorkloadJob) Kind() string { return KindAddWorkload }

func (a AddWorkloadJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       KindAddWorkload,
		MaxAttempts: 4,
	}
}

type AddWorkloadWorker struct {
	Querier   sql.Querier
	JobClient riverjob.Client
	Log       logrus.FieldLogger
	river.WorkerDefaults[AddWorkloadJob]
}

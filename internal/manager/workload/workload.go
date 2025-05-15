package workload

import (
	"context"
	"fmt"
	"github.com/nais/v13s/internal/manager/clients"
	"github.com/nais/v13s/internal/model"
	"github.com/riverqueue/river"
)

type AddWorkloadArgs struct {
	Workload *model.Workload
}

func (AddWorkloadArgs) Kind() string { return "addWorkload" }

type AddWorkloadWorker struct {
	river.WorkerDefaults[AddWorkloadArgs]
}

func (w *AddWorkloadWorker) Work(ctx context.Context, job *river.Job[AddWorkloadArgs]) error {
	m := clients.FromContext(ctx)
	fmt.Printf("mgr: %+v\n", m)
	fmt.Printf("working workload: %+v\n", job.Args.Workload)
	return nil
}

func RegisterAddWorkloadWorker(ctx context.Context) {
	a := &AddWorkloadWorker{}
	// IDEA will show cannot infer T, but is a bug in the IDE
	clients.AddWorker(ctx, a)
}

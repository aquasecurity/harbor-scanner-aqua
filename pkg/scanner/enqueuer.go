package scanner

import (
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/job"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/persistence"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/work"
	"github.com/google/uuid"
	"golang.org/x/xerrors"
)

// Enqueuer wraps the Enqueue method.
// Enqueue enqueues the specify ScanRequest for async processing and returns the async job's identifier.
type Enqueuer interface {
	Enqueue(request harbor.ScanRequest) (string, error)
}

// NewEnqueuer constructs the default Enqueuer.
func NewEnqueuer(pool *work.Pool, adapter Adapter, store persistence.Store) Enqueuer {
	return &enqueuer{
		pool:    pool,
		adapter: adapter,
		store:   store,
	}
}

type enqueuer struct {
	store   persistence.Store
	pool    *work.Pool
	adapter Adapter
}

func (e *enqueuer) Enqueue(request harbor.ScanRequest) (string, error) {
	jobID := uuid.New().String()
	err := e.store.Create(job.ScanJob{
		ID:     jobID,
		Status: job.Pending},
	)
	if err != nil {
		return "", xerrors.Errorf("creating scan job: %w", err)
	}
	e.pool.Run(&worker{
		store:   e.store,
		adapter: e.adapter,
		jobID:   jobID,
		request: request,
	})
	return jobID, nil
}

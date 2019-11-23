package persistence

import (
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/job"
)

// Store defines methods for persisting ScanJobs and associated ScanReports.
type Store interface {
	Create(scanJob job.ScanJob) error
	Get(scanJobID string) (*job.ScanJob, error)
	UpdateStatus(scanJobID string, newStatus job.Status, error ...string) error
	UpdateReport(scanJobID string, reports harbor.ScanReport) error
}

package grpcvulnerabilities

import (
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
)

// deriveSbomStatus maps internal image/workload state to a client-facing SbomStatus enum.
// Workload state takes precedence over image state.
func deriveSbomStatus(imageState sql.ImageState, workloadState sql.WorkloadState) vulnerabilities.SbomStatus {
	switch workloadState {
	case sql.WorkloadStateFailed, sql.WorkloadStateUnrecoverable:
		return vulnerabilities.SbomStatus_SBOM_STATUS_FAILED
	case sql.WorkloadStateNoAttestation:
		return vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM
	case sql.WorkloadStateProcessing:
		return vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING
	}

	switch imageState {
	case sql.ImageStateUpdated:
		return vulnerabilities.SbomStatus_SBOM_STATUS_READY
	case sql.ImageStateFailed:
		return vulnerabilities.SbomStatus_SBOM_STATUS_FAILED
	case sql.ImageStateUntracked, sql.ImageStateUnused:
		return vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM
	default: // initialized, resync, outdated → pipeline queued/running
		return vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING
	}
}

// sbomStatusPriority returns the numeric priority of a status for worst-case comparison.
// Higher value = worse / higher priority.
var sbomStatusPriority = map[vulnerabilities.SbomStatus]int{
	// Higher value = worse. PROCESSING is the accumulator sentinel (lowest priority)
	// since it means "we're working on it" — any definitive outcome is worse or equal.
	vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING: 0,
	vulnerabilities.SbomStatus_SBOM_STATUS_READY:      1,
	vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM:    2,
	vulnerabilities.SbomStatus_SBOM_STATUS_FAILED:     3,
}

// worstCase returns the status with the higher priority (i.e. the "worse" one).
func worstCase(a, b vulnerabilities.SbomStatus) vulnerabilities.SbomStatus {
	if sbomStatusPriority[a] >= sbomStatusPriority[b] {
		return a
	}
	return b
}

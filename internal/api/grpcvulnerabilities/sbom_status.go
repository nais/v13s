package grpcvulnerabilities

import (
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
)

func deriveSbomStatus(imageState sql.ImageState, workloadState sql.WorkloadState) vulnerabilities.SbomStatus {
	switch workloadState {
	case sql.WorkloadStateFailed, sql.WorkloadStateUnrecoverable:
		return vulnerabilities.SbomStatus_SBOM_STATUS_FAILED
	case sql.WorkloadStateNoAttestation:
		return vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM
	case sql.WorkloadStateProcessing:
		return vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING
	}

	return deriveImageSbomStatus(imageState)
}

func deriveImageSbomStatus(imageState sql.ImageState) vulnerabilities.SbomStatus {
	switch imageState {
	case sql.ImageStateUpdated:
		return vulnerabilities.SbomStatus_SBOM_STATUS_READY
	case sql.ImageStateFailed:
		return vulnerabilities.SbomStatus_SBOM_STATUS_FAILED
	case sql.ImageStateUntracked, sql.ImageStateUnused:
		return vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM
	default:
		return vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING
	}
}

var sbomStatusPriority = map[vulnerabilities.SbomStatus]int{
	vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING: 0,
	vulnerabilities.SbomStatus_SBOM_STATUS_READY:      1,
	vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM:    2,
	vulnerabilities.SbomStatus_SBOM_STATUS_FAILED:     3,
}

func worstCase(a, b vulnerabilities.SbomStatus) vulnerabilities.SbomStatus {
	if sbomStatusPriority[a] >= sbomStatusPriority[b] {
		return a
	}
	return b
}

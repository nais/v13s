package grpcvulnerabilities

import (
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func deriveSbomStatus(imageState sql.NullImageState, workloadState sql.WorkloadState, processingStartedAt *timestamppb.Timestamp) *vulnerabilities.SbomStatusInfo {
	switch workloadState {
	case sql.WorkloadStateFailed, sql.WorkloadStateUnrecoverable:
		return &vulnerabilities.SbomStatusInfo{Status: vulnerabilities.SbomStatus_SBOM_STATUS_FAILED}
	case sql.WorkloadStateNoAttestation:
		return &vulnerabilities.SbomStatusInfo{Status: vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM}
	case sql.WorkloadStateProcessing:
		return &vulnerabilities.SbomStatusInfo{Status: vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING}
	}

	if !imageState.Valid {
		return &vulnerabilities.SbomStatusInfo{Status: vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM}
	}
	return deriveImageSbomStatus(imageState.ImageState, processingStartedAt)
}

func deriveImageSbomStatus(imageState sql.ImageState, processingStartedAt *timestamppb.Timestamp) *vulnerabilities.SbomStatusInfo {
	var status vulnerabilities.SbomStatus
	switch imageState {
	case sql.ImageStateUpdated:
		status = vulnerabilities.SbomStatus_SBOM_STATUS_READY
	case sql.ImageStateFailed:
		status = vulnerabilities.SbomStatus_SBOM_STATUS_FAILED
	case sql.ImageStateUntracked, sql.ImageStateUnused:
		status = vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM
	default:
		status = vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING
	}
	return &vulnerabilities.SbomStatusInfo{
		Status:              status,
		ProcessingStartedAt: processingStartedAt,
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

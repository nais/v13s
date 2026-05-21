package grpcvulnerabilities

import (
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var sbomStatusPriority = map[vulnerabilities.SbomStatus]int{
	vulnerabilities.SbomStatus_SBOM_STATUS_UNSPECIFIED: -1,
	vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING:  0,
	vulnerabilities.SbomStatus_SBOM_STATUS_READY:       1,
	vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM:     2,
	vulnerabilities.SbomStatus_SBOM_STATUS_FAILED:      3,
}

func worstCase(a, b vulnerabilities.SbomStatus) vulnerabilities.SbomStatus {
	if sbomStatusPriority[a] >= sbomStatusPriority[b] {
		return a
	}
	return b
}

func deriveImageSbomStatus(imageState *sql.ImageState) vulnerabilities.SbomStatus {
	if imageState == nil {
		return vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM
	}
	switch *imageState {
	case sql.ImageStateUpdated:
		return vulnerabilities.SbomStatus_SBOM_STATUS_READY
	case sql.ImageStateFailed:
		return vulnerabilities.SbomStatus_SBOM_STATUS_FAILED
	case sql.ImageStateUnused:
		return vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM
	default:
		return vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING
	}
}

func deriveSbomStatus(workloadState sql.WorkloadState, imageState *sql.ImageState) vulnerabilities.SbomStatus {
	switch workloadState {
	case sql.WorkloadStateFailed, sql.WorkloadStateUnrecoverable:
		return vulnerabilities.SbomStatus_SBOM_STATUS_FAILED
	case sql.WorkloadStateNoAttestation:
		return vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM
	default:
		return deriveImageSbomStatus(imageState)
	}
}

func isPendingSbomStatus(s vulnerabilities.SbomStatus) bool {
	return s == vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING ||
		s == vulnerabilities.SbomStatus_SBOM_STATUS_UNSPECIFIED
}

func sbomStatusInfo(workloadState sql.WorkloadState, imageState *sql.ImageState, processingStartedAt pgtype.Timestamptz) *vulnerabilities.SbomStatusInfo {
	status := deriveSbomStatus(workloadState, imageState)
	info := &vulnerabilities.SbomStatusInfo{
		Status: status,
	}
	if processingStartedAt.Valid {
		info.ProcessingStartedAt = timestamppb.New(processingStartedAt.Time)
	}
	return info
}

package grpcvulnerabilities

import (
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var sbomStatusPriority = map[vulnerabilities.SbomStatus]int{
	vulnerabilities.SbomStatus_SBOM_STATUS_UNSPECIFIED: -1,
	vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING:  0,
	vulnerabilities.SbomStatus_SBOM_STATUS_READY:       1,
	vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM:     2,
	vulnerabilities.SbomStatus_SBOM_STATUS_FAILED:      3,
}

var sbomStatusNames = map[vulnerabilities.SbomStatus]string{
	vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING: "processing",
	vulnerabilities.SbomStatus_SBOM_STATUS_READY:      "ready",
	vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM:    "no_sbom",
	vulnerabilities.SbomStatus_SBOM_STATUS_FAILED:     "failed",
}

func sbomStatusNamesFromFilter(filter []vulnerabilities.SbomStatus) ([]string, error) {
	if len(filter) == 0 {
		return nil, nil
	}

	statuses := make([]string, 0, len(filter))
	for _, sbomStatus := range filter {
		name, ok := sbomStatusNames[sbomStatus]
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "invalid SBOM status: %s", sbomStatus)
		}
		statuses = append(statuses, name)
	}
	return statuses, nil
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

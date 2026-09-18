package grpcvulnerabilities

import (
	"testing"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDeriveSbomStatus(t *testing.T) {
	updatedImage := sql.ImageStateUpdated
	failedImage := sql.ImageStateFailed
	initImage := sql.ImageStateInitialized

	tests := []struct {
		name          string
		workloadState sql.WorkloadState
		imageState    *sql.ImageState
		want          vulnerabilities.SbomStatus
	}{
		{
			name:          "workload failed => FAILED",
			workloadState: sql.WorkloadStateFailed,
			imageState:    &updatedImage,
			want:          vulnerabilities.SbomStatus_SBOM_STATUS_FAILED,
		},
		{
			name:          "workload unrecoverable => FAILED",
			workloadState: sql.WorkloadStateUnrecoverable,
			imageState:    &updatedImage,
			want:          vulnerabilities.SbomStatus_SBOM_STATUS_FAILED,
		},
		{
			name:          "workload no_attestation => NO_SBOM",
			workloadState: sql.WorkloadStateNoAttestation,
			imageState:    nil,
			want:          vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM,
		},
		{
			name:          "workload updated, image updated => READY",
			workloadState: sql.WorkloadStateUpdated,
			imageState:    &updatedImage,
			want:          vulnerabilities.SbomStatus_SBOM_STATUS_READY,
		},
		{
			name:          "workload updated, image still processing => PROCESSING",
			workloadState: sql.WorkloadStateUpdated,
			imageState:    &initImage,
			want:          vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING,
		},
		{
			name:          "workload updated, no image yet => NO_SBOM",
			workloadState: sql.WorkloadStateUpdated,
			imageState:    nil,
			want:          vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM,
		},
		{
			name:          "workload processing, image updated => READY",
			workloadState: sql.WorkloadStateProcessing,
			imageState:    &updatedImage,
			want:          vulnerabilities.SbomStatus_SBOM_STATUS_READY,
		},
		{
			name:          "workload processing, image failed => FAILED",
			workloadState: sql.WorkloadStateProcessing,
			imageState:    &failedImage,
			want:          vulnerabilities.SbomStatus_SBOM_STATUS_FAILED,
		},
		{
			name:          "workload processing, image initialized => PROCESSING",
			workloadState: sql.WorkloadStateProcessing,
			imageState:    &initImage,
			want:          vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING,
		},
		{
			name:          "workload initialized, no image => NO_SBOM",
			workloadState: sql.WorkloadStateInitialized,
			imageState:    nil,
			want:          vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveSbomStatus(tc.workloadState, tc.imageState)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestDeriveImageSbomStatus(t *testing.T) {
	updatedImage := sql.ImageStateUpdated
	failedImage := sql.ImageStateFailed
	initImage := sql.ImageStateInitialized

	tests := []struct {
		name       string
		imageState *sql.ImageState
		want       vulnerabilities.SbomStatus
	}{
		{"nil => NO_SBOM", nil, vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM},
		{"updated => READY", &updatedImage, vulnerabilities.SbomStatus_SBOM_STATUS_READY},
		{"failed => FAILED", &failedImage, vulnerabilities.SbomStatus_SBOM_STATUS_FAILED},
		{"initialized => PROCESSING", &initImage, vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveImageSbomStatus(tc.imageState)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestWorstCase(t *testing.T) {
	tests := []struct {
		a, b vulnerabilities.SbomStatus
		want vulnerabilities.SbomStatus
	}{
		{vulnerabilities.SbomStatus_SBOM_STATUS_READY, vulnerabilities.SbomStatus_SBOM_STATUS_FAILED, vulnerabilities.SbomStatus_SBOM_STATUS_FAILED},
		{vulnerabilities.SbomStatus_SBOM_STATUS_FAILED, vulnerabilities.SbomStatus_SBOM_STATUS_READY, vulnerabilities.SbomStatus_SBOM_STATUS_FAILED},
		{vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING, vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM, vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM},
		{vulnerabilities.SbomStatus_SBOM_STATUS_READY, vulnerabilities.SbomStatus_SBOM_STATUS_READY, vulnerabilities.SbomStatus_SBOM_STATUS_READY},
		{vulnerabilities.SbomStatus_SBOM_STATUS_UNSPECIFIED, vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING, vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING},
	}

	for _, tc := range tests {
		t.Run(tc.a.String()+"_vs_"+tc.b.String(), func(t *testing.T) {
			got := worstCase(tc.a, tc.b)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSbomStatusNamesFromFilter(t *testing.T) {
	tests := []struct {
		name        string
		filter      *vulnerabilities.Filter
		want        []string
		wantErrCode codes.Code
	}{
		{
			name:   "nil filter",
			filter: nil,
		},
		{
			name:   "empty statuses",
			filter: &vulnerabilities.Filter{},
		},
		{
			name: "supported statuses",
			filter: &vulnerabilities.Filter{SbomStatuses: []vulnerabilities.SbomStatus{
				vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING,
				vulnerabilities.SbomStatus_SBOM_STATUS_READY,
				vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM,
				vulnerabilities.SbomStatus_SBOM_STATUS_FAILED,
			}},
			want: []string{"processing", "ready", "no_sbom", "failed"},
		},
		{
			name: "unspecified status",
			filter: &vulnerabilities.Filter{SbomStatuses: []vulnerabilities.SbomStatus{
				vulnerabilities.SbomStatus_SBOM_STATUS_UNSPECIFIED,
			}},
			wantErrCode: codes.InvalidArgument,
		},
		{
			name: "unknown status",
			filter: &vulnerabilities.Filter{SbomStatuses: []vulnerabilities.SbomStatus{
				vulnerabilities.SbomStatus(99),
			}},
			wantErrCode: codes.InvalidArgument,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sbomStatusNamesFromFilter(tc.filter)
			if tc.wantErrCode != codes.OK {
				require.Error(t, err)
				assert.Equal(t, tc.wantErrCode, status.Code(err))
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

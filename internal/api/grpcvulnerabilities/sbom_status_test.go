package grpcvulnerabilities

import (
	"testing"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
)

func TestDeriveSbomStatus(t *testing.T) {
	tests := []struct {
		name          string
		imageState    sql.ImageState
		workloadState sql.WorkloadState
		want          vulnerabilities.SbomStatus
	}{
		{
			name:          "workload failed → FAILED",
			imageState:    sql.ImageStateUpdated,
			workloadState: sql.WorkloadStateFailed,
			want:          vulnerabilities.SbomStatus_SBOM_STATUS_FAILED,
		},
		{
			name:          "workload unrecoverable → FAILED",
			imageState:    sql.ImageStateUpdated,
			workloadState: sql.WorkloadStateUnrecoverable,
			want:          vulnerabilities.SbomStatus_SBOM_STATUS_FAILED,
		},
		{
			name:          "workload no_sbom → NO_SBOM",
			imageState:    sql.ImageStateUpdated,
			workloadState: sql.WorkloadStateNoAttestation,
			want:          vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM,
		},
		{
			name:          "workload processing → PROCESSING",
			imageState:    sql.ImageStateInitialized,
			workloadState: sql.WorkloadStateProcessing,
			want:          vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING,
		},
		{
			name:          "image updated, workload updated → READY",
			imageState:    sql.ImageStateUpdated,
			workloadState: sql.WorkloadStateUpdated,
			want:          vulnerabilities.SbomStatus_SBOM_STATUS_READY,
		},
		{
			name:          "image failed → FAILED",
			imageState:    sql.ImageStateFailed,
			workloadState: sql.WorkloadStateInitialized,
			want:          vulnerabilities.SbomStatus_SBOM_STATUS_FAILED,
		},
		{
			name:          "image untracked → NO_SBOM",
			imageState:    sql.ImageStateUntracked,
			workloadState: sql.WorkloadStateInitialized,
			want:          vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM,
		},
		{
			name:          "image unused → NO_SBOM",
			imageState:    sql.ImageStateUnused,
			workloadState: sql.WorkloadStateInitialized,
			want:          vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM,
		},
		{
			name:          "image initialized → PROCESSING",
			imageState:    sql.ImageStateInitialized,
			workloadState: sql.WorkloadStateInitialized,
			want:          vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING,
		},
		{
			name:          "image resync → PROCESSING",
			imageState:    sql.ImageStateResync,
			workloadState: sql.WorkloadStateResync,
			want:          vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING,
		},
		{
			name:          "image outdated → PROCESSING",
			imageState:    sql.ImageStateOutdated,
			workloadState: sql.WorkloadStateInitialized,
			want:          vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deriveSbomStatus(tt.imageState, tt.workloadState)
			if got.GetStatus() != tt.want {
				t.Errorf("deriveSbomStatus() = %v, want %v", got.GetStatus(), tt.want)
			}
		})
	}
}

func TestWorstCase(t *testing.T) {
	tests := []struct {
		a, b vulnerabilities.SbomStatus
		want vulnerabilities.SbomStatus
	}{
		{
			a:    vulnerabilities.SbomStatus_SBOM_STATUS_READY,
			b:    vulnerabilities.SbomStatus_SBOM_STATUS_FAILED,
			want: vulnerabilities.SbomStatus_SBOM_STATUS_FAILED,
		},
		{
			a:    vulnerabilities.SbomStatus_SBOM_STATUS_FAILED,
			b:    vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM,
			want: vulnerabilities.SbomStatus_SBOM_STATUS_FAILED,
		},
		{
			a:    vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING,
			b:    vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM,
			want: vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM,
		},
		{
			a:    vulnerabilities.SbomStatus_SBOM_STATUS_READY,
			b:    vulnerabilities.SbomStatus_SBOM_STATUS_READY,
			want: vulnerabilities.SbomStatus_SBOM_STATUS_READY,
		},
		{
			a:    vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING,
			b:    vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM,
			want: vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM,
		},
		{
			a:    vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING,
			b:    vulnerabilities.SbomStatus_SBOM_STATUS_READY,
			want: vulnerabilities.SbomStatus_SBOM_STATUS_READY,
		},
	}

	for _, tt := range tests {
		t.Run(tt.a.String()+"_vs_"+tt.b.String(), func(t *testing.T) {
			got := worstCase(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("worstCase(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
			got2 := worstCase(tt.b, tt.a)
			if got2 != tt.want {
				t.Errorf("worstCase(%v, %v) [commuted] = %v, want %v", tt.b, tt.a, got2, tt.want)
			}
		})
	}
}

func TestWorstCaseRollup(t *testing.T) {
	tests := []struct {
		name     string
		statuses []vulnerabilities.SbomStatus
		want     vulnerabilities.SbomStatus
	}{
		{
			name: "all READY → READY",
			statuses: []vulnerabilities.SbomStatus{
				vulnerabilities.SbomStatus_SBOM_STATUS_READY,
				vulnerabilities.SbomStatus_SBOM_STATUS_READY,
			},
			want: vulnerabilities.SbomStatus_SBOM_STATUS_READY,
		},
		{
			name: "one FAILED dominates all others",
			statuses: []vulnerabilities.SbomStatus{
				vulnerabilities.SbomStatus_SBOM_STATUS_READY,
				vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM,
				vulnerabilities.SbomStatus_SBOM_STATUS_FAILED,
				vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING,
			},
			want: vulnerabilities.SbomStatus_SBOM_STATUS_FAILED,
		},
		{
			name: "NO_SBOM beats PROCESSING",
			statuses: []vulnerabilities.SbomStatus{
				vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING,
				vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM,
			},
			want: vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM,
		},
		{
			name: "single READY workload",
			statuses: []vulnerabilities.SbomStatus{
				vulnerabilities.SbomStatus_SBOM_STATUS_READY,
			},
			want: vulnerabilities.SbomStatus_SBOM_STATUS_READY,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acc := vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING
			for _, s := range tt.statuses {
				acc = worstCase(acc, s)
			}
			if acc != tt.want {
				t.Errorf("rollup = %v, want %v", acc, tt.want)
			}
		})
	}
}

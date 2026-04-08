package grpcvulnerabilities

import (
	"testing"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/stretchr/testify/assert"
)

func TestCalculateStaleSeverity(t *testing.T) {
	t.Run("returns STALE_NONE when summary is not stale and image state is valid", func(t *testing.T) {
		result := CalculateStaleSeverity(
			false,
			true,
			sql.NullImageState{ImageState: sql.ImageStateUpdated, Valid: true},
			nil,
			"v1.0.0",
			"",
		)
		assert.Equal(t, vulnerabilities.StaleSeverity_STALE_NONE, result.Severity)
		assert.Equal(t, "SBOM is up to date", result.Reason)
	})

	t.Run("returns STALE_PROCESSING when summary is stale with fallback", func(t *testing.T) {
		result := CalculateStaleSeverity(
			true,
			true,
			sql.NullImageState{ImageState: sql.ImageStateUpdated, Valid: true},
			nil,
			"v2.0.0",
			"v1.0.0",
		)
		assert.Equal(t, vulnerabilities.StaleSeverity_STALE_PROCESSING, result.Severity)
		assert.Contains(t, result.Reason, "SBOM for tag v2.0.0 is being processed")
		assert.Contains(t, result.Reason, "showing data from v1.0.0")
	})

	t.Run("returns STALE_PROCESSING when summary is stale without fallback", func(t *testing.T) {
		result := CalculateStaleSeverity(
			true,
			true,
			sql.NullImageState{ImageState: sql.ImageStateUpdated, Valid: true},
			nil,
			"v2.0.0",
			"",
		)
		assert.Equal(t, vulnerabilities.StaleSeverity_STALE_PROCESSING, result.Severity)
		assert.Contains(t, result.Reason, "SBOM for tag v2.0.0 is being processed")
	})

	t.Run("returns STALE_PERMANENT for untracked image WITHOUT sbom", func(t *testing.T) {
		result := CalculateStaleSeverity(
			true,
			false,
			sql.NullImageState{ImageState: sql.ImageStateUntracked, Valid: true},
			nil,
			"v1.0.0",
			"",
		)
		assert.Equal(t, vulnerabilities.StaleSeverity_STALE_PERMANENT, result.Severity)
		assert.Contains(t, result.Reason, "no SBOM found for image tag v1.0.0")
	})

	t.Run("returns STALE_PROCESSING for untracked image WITH fallback sbom", func(t *testing.T) {
		result := CalculateStaleSeverity(
			true,
			true,
			sql.NullImageState{ImageState: sql.ImageStateUntracked, Valid: true},
			nil,
			"v2.0.0",
			"v1.0.0",
		)
		assert.Equal(t, vulnerabilities.StaleSeverity_STALE_PROCESSING, result.Severity)
		assert.Contains(t, result.Reason, "showing data from v1.0.0")
		assert.NotContains(t, result.Reason, "no SBOM found")
	})

	t.Run("returns STALE_PERMANENT for failed image WITHOUT sbom", func(t *testing.T) {
		result := CalculateStaleSeverity(
			true,
			false,
			sql.NullImageState{ImageState: sql.ImageStateFailed, Valid: true},
			nil,
			"v1.0.0",
			"",
		)
		assert.Equal(t, vulnerabilities.StaleSeverity_STALE_PERMANENT, result.Severity)
		assert.Contains(t, result.Reason, "failed to upload SBOM for image tag v1.0.0")
	})

	t.Run("returns STALE_PERMANENT for failed image WITH fallback sbom", func(t *testing.T) {
		result := CalculateStaleSeverity(
			true,
			true,
			sql.NullImageState{ImageState: sql.ImageStateFailed, Valid: true},
			nil,
			"v2.0.0",
			"v1.0.0",
		)
		assert.Equal(t, vulnerabilities.StaleSeverity_STALE_PERMANENT, result.Severity)
		assert.Contains(t, result.Reason, "failed to upload SBOM for image tag v2.0.0")
		assert.Contains(t, result.Reason, "showing data from v1.0.0")
	})

	t.Run("returns STALE_PERMANENT for workload with no attestation", func(t *testing.T) {
		workloadState := sql.WorkloadStateNoAttestation
		result := CalculateStaleSeverity(
			false,
			false,
			sql.NullImageState{},
			&workloadState,
			"v1.0.0",
			"",
		)
		assert.Equal(t, vulnerabilities.StaleSeverity_STALE_PERMANENT, result.Severity)
		assert.Contains(t, result.Reason, "no attestation found for image tag v1.0.0")
	})

	t.Run("returns STALE_PERMANENT for workload with no attestation but with fallback", func(t *testing.T) {
		workloadState := sql.WorkloadStateNoAttestation
		result := CalculateStaleSeverity(
			true,
			true,
			sql.NullImageState{},
			&workloadState,
			"v2.0.0",
			"v1.0.0",
		)
		assert.Equal(t, vulnerabilities.StaleSeverity_STALE_PERMANENT, result.Severity)
		assert.Contains(t, result.Reason, "no attestation found for image tag v2.0.0")
		assert.Contains(t, result.Reason, "showing data from v1.0.0")
	})

	t.Run("returns STALE_NONE when image state is NULL", func(t *testing.T) {
		result := CalculateStaleSeverity(
			false,
			true,
			sql.NullImageState{Valid: false},
			nil,
			"v1.0.0",
			"",
		)
		assert.Equal(t, vulnerabilities.StaleSeverity_STALE_NONE, result.Severity)
	})

	t.Run("returns STALE_NONE when image state is failed but summary is NOT stale", func(t *testing.T) {
		result := CalculateStaleSeverity(
			false,
			true,
			sql.NullImageState{ImageState: sql.ImageStateFailed, Valid: true},
			nil,
			"v1.0.0",
			"",
		)
		assert.Equal(t, vulnerabilities.StaleSeverity_STALE_NONE, result.Severity)
		assert.Equal(t, "SBOM is up to date", result.Reason)
	})
}

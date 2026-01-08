package grpcvulnerabilities

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *Server) GetImageSbomStatus(ctx context.Context, request *vulnerabilities.GetImageSbomStatusRequest) (*vulnerabilities.GetImageSbomStatusResponse, error) {
	row, err := s.querier.GetImageSbomStatus(ctx, sql.GetImageSbomStatusParams{
		ImageName: request.ImageName,
		ImageTag:  request.ImageTag,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Error(codes.NotFound, fmt.Sprintf("no SBOM status found for image %s:%s", request.ImageName, request.ImageTag))
		}
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to get SBOM status for image %s:%s: %v", request.ImageName, request.ImageTag, err))
	}

	return &vulnerabilities.GetImageSbomStatusResponse{
		SbomStatus: &vulnerabilities.ImageSbomStatus{
			SbomPresent: !row.Pending,
			UpdatedAt:   timestamppb.New(row.UpdatedAt.Time),
		},
	}, nil
}

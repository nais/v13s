package auth

import (
	"context"
	"strings"

	"cloud.google.com/go/auth/credentials/idtoken"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/nais/v13s/internal/collections"
)

var (
	ErrMissingMetadata = status.Errorf(codes.InvalidArgument, "missing metadata")
	ErrMissingToken    = status.Errorf(codes.Unauthenticated, "missing token")
)

type googleIDTokenValidator struct {
	audience                  string
	authorizedServiceAccounts []string
	log                       *log.Entry
}

func TokenInterceptor(audience string, authorizedServiceAccounts []string, field *log.Entry) grpc.UnaryServerInterceptor {
	g := &googleIDTokenValidator{
		audience:                  audience,
		authorizedServiceAccounts: authorizedServiceAccounts,
		log:                       field,
	}
	return g.ensureValidToken
}

// TODO: when necessary add authorization per method, i.e. only slsa-verde can RegisterWorkload etc.
func (g *googleIDTokenValidator) ensureValidToken(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, ErrMissingMetadata
	}

	// The keys within metadata.MD are normalized to lowercase.
	// See: https://godoc.org/google.golang.org/grpc/metadata#New
	if err = g.valid(ctx, md["authorization"]); err != nil {
		return nil, err
	}
	// Continue execution of handler after ensuring a valid token.
	return handler(ctx, req)
}

func (g *googleIDTokenValidator) valid(ctx context.Context, authorization []string) error {
	if len(authorization) < 1 {
		g.log.Warn("Missing authorization token")
		return ErrMissingToken
	}

	token := strings.TrimPrefix(authorization[0], "Bearer ")
	payload, err := idtoken.Validate(ctx, token, g.audience)
	if err != nil {
		g.log.Errorf("failed to validate token: %v", err)
		return status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
	}

	email, ok := payload.Claims["email"].(string)
	if !ok {
		g.log.Error("missing or invalid email claim in token")
		return status.Errorf(codes.Unauthenticated, "invalid token payload")
	}

	g.log.Debugf("token validated successfully for email: %s", email)

	authorized := collections.AnyMatch(g.authorizedServiceAccounts, func(s string) bool {
		if !strings.HasSuffix(s, ".iam.gserviceaccount.com") {
			s = s + ".iam.gserviceaccount.com"
		}
		return s == email
	})

	if !authorized {
		g.log.Warnf("unauthorized service account: %s", email)
		return status.Errorf(codes.PermissionDenied, "unauthorized service account")
	}

	g.log.Debugf("valid token for authorized service account: %s", email)
	return nil
}

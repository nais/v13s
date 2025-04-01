package auth

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
	"google.golang.org/api/impersonate"
	"google.golang.org/grpc/credentials"
)

var _ credentials.PerRPCCredentials = anyTransportPerRPCCredentials{}

func PerRPCGoogleIDToken(ctx context.Context, serviceAccountEmail, audience string) (credentials.PerRPCCredentials, error) {
	ts, err := gcpTokenSource(ctx, serviceAccountEmail, audience)
	if err != nil {
		return nil, err
	}
	return anyTransportPerRPCCredentials{
		tokenSrc: ts,
	}, nil
}

func gcpTokenSource(ctx context.Context, serviceAccountEmail, audience string) (oauth2.TokenSource, error) {
	return impersonate.IDTokenSource(ctx,
		impersonate.IDTokenConfig{
			TargetPrincipal: serviceAccountEmail,
			Audience:        audience,
			IncludeEmail:    true,
		},
	)
}

type anyTransportPerRPCCredentials struct {
	tokenSrc oauth2.TokenSource
}

func (i anyTransportPerRPCCredentials) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	//return i.tokenSrc.GetRequestMetadata(ctx, uri...)
	token, err := i.tokenSrc.Token()
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"authorization": fmt.Sprintf("Bearer %s", token.AccessToken),
	}, nil
}

func (i anyTransportPerRPCCredentials) RequireTransportSecurity() bool {
	return false
}

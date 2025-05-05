package auth_test

import (
	"context"
	"errors"
	"testing"

	"cloud.google.com/go/auth/credentials/idtoken"
	"github.com/nais/v13s/internal/api/auth"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestEnsureValidToken(t *testing.T) {
	authorized := []string{"ok-sa"}

	type testCase struct {
		name         string
		metadata     metadata.MD
		validateFunc auth.ValidateFuncType
		expectErrMsg string
		expectResp   any
	}

	testCases := []testCase{
		{
			name:         "missing metadata",
			metadata:     nil,
			validateFunc: nil,
			expectErrMsg: "missing metadata",
		},
		{
			name:         "missing authorization header",
			metadata:     metadata.New(map[string]string{}),
			validateFunc: nil,
			expectErrMsg: "missing token",
		},
		{
			name: "invalid token",
			metadata: metadata.New(map[string]string{
				"authorization": "Bearer invalid-token",
			}),
			validateFunc: func(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
				return nil, errors.New("token invalid")
			},
			expectErrMsg: "invalid token: token invalid",
		},
		{
			name: "missing email claim",
			metadata: metadata.New(map[string]string{
				"authorization": "Bearer token-without-email",
			}),
			validateFunc: func(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
				return &idtoken.Payload{Claims: map[string]interface{}{}}, nil
			},
			expectErrMsg: "invalid token payload",
		},
		{
			name: "unauthorized service account",
			metadata: metadata.New(map[string]string{
				"authorization": "Bearer token-bad-email",
			}),
			validateFunc: func(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
				return &idtoken.Payload{
					Claims: map[string]interface{}{
						"email": "unauthorized@svc.iam.gserviceaccount.com",
					},
				}, nil
			},
			expectErrMsg: "unauthorized service account",
		},
		{
			name: "invalid audience",
			metadata: metadata.New(map[string]string{
				"authorization": "Bearer token-wrong-audience",
			}),
			validateFunc: func(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
				if audience != "expected-audience" {
					return nil, errors.New("audience mismatch")
				}
				return &idtoken.Payload{
					Claims: map[string]interface{}{
						"email": "good-sa.iam.gserviceaccount.com",
					},
				}, nil
			},
			expectErrMsg: "invalid token: audience mismatch",
		},
		{
			name: "valid request",
			metadata: metadata.New(map[string]string{
				"authorization": "Bearer valid-token",
			}),
			validateFunc: func(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
				return &idtoken.Payload{
					Claims: map[string]interface{}{
						"email": "ok-sa.iam.gserviceaccount.com",
					},
				}, nil
			},
			expectResp: "OK",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator := auth.NewGoogleIDTokenValidator(
				"test-audience",
				authorized,
				log.NewEntry(log.New()),
				withFallback(tc.validateFunc),
			)

			ctx := context.Background()
			if tc.metadata != nil {
				ctx = metadata.NewIncomingContext(ctx, tc.metadata)
			}

			resp, err := validator.EnsureValidToken(
				ctx,
				nil,
				&grpc.UnaryServerInfo{FullMethod: "/some.Method"},
				func(ctx context.Context, req any) (any, error) {
					return "OK", nil
				},
			)

			if tc.expectErrMsg != "" {
				assert.Error(t, err)
				st, _ := status.FromError(err)
				assert.Contains(t, st.Message(), tc.expectErrMsg)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectResp, resp)
			}
		})
	}
}

func withFallback(f auth.ValidateFuncType) auth.ValidateFuncType {
	if f != nil {
		return f
	}
	return func(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
		return nil, nil
	}
}

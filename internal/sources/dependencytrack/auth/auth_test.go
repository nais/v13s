package auth

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nais/v13s/internal/sources/dependencytrack/client"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestUsernamePasswordSource_ContextHeaders(t *testing.T) {
	mockUserAPI := new(client.MockUserAPI)
	mockTeamAPI := new(client.MockTeamAPI)

	mockClient := &client.APIClient{
		UserAPI: mockUserAPI,
		TeamAPI: mockTeamAPI,
	}

	mockUserAPI.On("ValidateCredentials", mock.Anything).Return(client.ApiValidateCredentialsRequest{
		ApiService: mockUserAPI,
	}).Once()

	token := generateSignedTestToken(t, 10*time.Minute)
	mockUserAPI.On("ValidateCredentialsExecute", mock.Anything).Return(
		token, nil, nil).Once()

	authSource := NewUsernamePasswordSource("user", "password", mockClient, log.WithField("subsystem", "test-auth-source"))

	ctx := context.Background()
	bearerCtx, err := authSource.ContextHeaders(ctx)
	assert.NoError(t, err)
	assert.Equal(t, token, bearerCtx.Value(client.ContextAccessToken))

	mockUserAPI.AssertExpectations(t)
	mockTeamAPI.AssertExpectations(t)

	// validate that the token is added in the context
	mockUserAPI.On("ValidateCredentials", mock.Anything).Return(client.ApiValidateCredentialsRequest{
		ApiService: mockUserAPI,
	}).Once()

	mockUserAPI.On("ValidateCredentialsExecute", mock.Anything).Return(
		token, nil, nil).Once()
	bearerCtx, err = authSource.ContextHeaders(ctx)
	assert.NoError(t, err)
	assert.Equal(t, token, bearerCtx.Value(client.ContextAccessToken))
}

func TestUsernamePasswordSource_ContextHeaders_Token_Validation(t *testing.T) {
	mockUserAPI := new(client.MockUserAPI)
	mockTeamAPI := new(client.MockTeamAPI)

	mockClient := &client.APIClient{
		UserAPI: mockUserAPI,
		TeamAPI: mockTeamAPI,
	}

	token := generateSignedTestToken(t, 10*time.Minute)
	authSource := newUsernamePasswordSourceWithToken("user", "password", token, mockClient, log.WithField("subsystem", "test-auth-source"))

	ctx := context.Background()

	t.Run("valid token returns context", func(t *testing.T) {
		bearerCtx, err := authSource.ContextHeaders(ctx)
		require.NoError(t, err)
		require.Equal(t, token, bearerCtx.Value(client.ContextAccessToken))

		mockUserAPI.AssertExpectations(t)
		mockTeamAPI.AssertExpectations(t)
	})

	t.Run("malformed token returns error on parsing", func(t *testing.T) {
		// Create a malformed token (append garbage to a valid token)
		expiredToken := generateSignedTestToken(t, -1*time.Hour)
		authSource = newUsernamePasswordSourceWithToken("user", "password", expiredToken, mockClient, log.WithField("subsystem", "test-auth-source"))
		token = "malformed.token.garbage"

		// Setup mock to return malformed token on login
		mockUserAPI.On("ValidateCredentials", mock.Anything).Return(client.ApiValidateCredentialsRequest{
			ApiService: mockUserAPI,
		}).Once()
		mockUserAPI.On("ValidateCredentialsExecute", mock.Anything).Return(token, nil, nil).Once()

		bearerCtx, err := authSource.ContextHeaders(ctx)
		// The first call returns error because the token is malformed, so context should be nil
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode")
		assert.Nil(t, bearerCtx)
	})

	t.Run("expired token triggers login and returns new token", func(t *testing.T) {
		expiredToken := generateSignedTestToken(t, -1*time.Hour)
		authSource = newUsernamePasswordSourceWithToken("user", "password", expiredToken, mockClient, log.WithField("subsystem", "test-auth-source"))
		validToken := generateSignedTestToken(t, 10*time.Minute)
		fmt.Println(validToken)

		// First returns an unsatisfied token (expired) in this case, from server after identifying expired token
		mockUserAPI.On("ValidateCredentials", mock.Anything).Return(client.ApiValidateCredentialsRequest{
			ApiService: mockUserAPI,
		}).Once()
		mockUserAPI.On("ValidateCredentialsExecute", mock.Anything).Return(expiredToken, nil, nil).Once()

		// Second login returns new valid token (triggered after expiration detected)
		mockUserAPI.On("ValidateCredentials", mock.Anything).Return(client.ApiValidateCredentialsRequest{
			ApiService: mockUserAPI,
		}).Once()
		mockUserAPI.On("ValidateCredentialsExecute", mock.Anything).Return(validToken, nil, nil).Once()

		_, err := authSource.ContextHeaders(ctx)
		assert.Error(t, err)

		// Next call detects expired token and triggers login to refresh token
		bearerCtx, err := authSource.ContextHeaders(ctx)
		assert.NoError(t, err)
		assert.Equal(t, validToken, bearerCtx.Value(client.ContextAccessToken))
		mockUserAPI.AssertExpectations(t)
	})

	t.Run("malformed token returns parse error", func(t *testing.T) {
		malformedToken := "this.is.not.a.valid.jwt"

		authSource = newUsernamePasswordSourceWithToken("user", "password", malformedToken, mockClient, log.WithField("subsystem", "test-auth-source"))

		// token is malformed, checkAccessToken should return an error
		_, _, err := authSource.checkAccessToken()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse access token")

		// ContextHeaders should propagate the error too
		_, err = authSource.ContextHeaders(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse access token")
	})

	t.Run("login fails with error", func(t *testing.T) {
		expiredToken := generateSignedTestToken(t, -1*time.Hour)
		authSource = newUsernamePasswordSourceWithToken("user", "password", expiredToken, mockClient, log.WithField("subsystem", "test-auth-source"))

		mockUserAPI.On("ValidateCredentials", mock.Anything).Return(client.ApiValidateCredentialsRequest{
			ApiService: mockUserAPI,
		}).Once()

		mockUserAPI.On("ValidateCredentialsExecute", mock.Anything).Return("", &http.Response{
			StatusCode: http.StatusInternalServerError,
			Status:     "500 Internal Server Error",
			Body:       nil,
		}, fmt.Errorf("login failed")).Once()

		_, err := authSource.ContextHeaders(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to validate credentials")

		mockUserAPI.AssertExpectations(t)
	})
}

func generateSignedTestToken(t *testing.T, expiryDelta time.Duration) string {
	token := jwt.New()

	err := token.Set(jwt.SubjectKey, "test-subject")
	assert.NoError(t, err)

	err = token.Set(jwt.IssuedAtKey, time.Now())
	assert.NoError(t, err)

	err = token.Set(jwt.ExpirationKey, time.Now().Add(expiryDelta))
	assert.NoError(t, err)

	// Use a dummy secret key for HMAC HS256 signing
	key := []byte("dummy-secret-key")

	// Sign the token and produce compact serialization (base64url encoded JWT string)
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.HS256, key))
	assert.NoError(t, err)

	return string(signed)
}

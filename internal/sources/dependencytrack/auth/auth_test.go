package auth

import (
	"context"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nais/v13s/internal/sources/dependencytrack/client"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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

	token := getToken()
	mockUserAPI.On("ValidateCredentialsExecute", mock.Anything).Return(
		getToken(), nil, nil).Once()

	authSource := NewUsernamePasswordSource("user", "password", mockClient, log.WithField("subsystem", "test-auth-source"))

	ctx := context.Background()
	bearerCtx, err := authSource.ContextHeaders(ctx)
	assert.NoError(t, err)
	assert.Equal(t, token, bearerCtx.Value(client.ContextAccessToken))

	mockUserAPI.AssertExpectations(t)
	mockTeamAPI.AssertExpectations(t)

	// validate that the token is still in the context
	mockUserAPI.On("ValidateCredentials", mock.Anything).Return(client.ApiValidateCredentialsRequest{
		ApiService: mockUserAPI,
	}).Once()

	mockUserAPI.On("ValidateCredentialsExecute", mock.Anything).Return(
		token, nil, nil).Once()
	bearerCtx, err = authSource.ContextHeaders(ctx)
	assert.NoError(t, err)
	assert.Equal(t, token, bearerCtx.Value(client.ContextAccessToken))
}

func getToken() string {
	j := jwt.New()
	ser := jwt.NewSerializer()
	token, err := ser.Serialize(j)
	if err != nil {
		panic(err)
	}
	return string(token)
}

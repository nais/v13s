package auth

import (
	"context"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nais/v13s/internal/sources/dependencytrack/client"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
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

	authSource := NewUsernamePasswordSource("user", "password", mockClient, nil)

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

func TestApiKeySource_ContextHeaders(t *testing.T) {
	mockUserAPI := new(client.MockUserAPI)
	mockTeamAPI := new(client.MockTeamAPI)

	mockClient := &client.APIClient{
		UserAPI: mockUserAPI,
		TeamAPI: mockTeamAPI,
	}

	mockUserAPI.On("ValidateCredentials", mock.Anything).Return(client.ApiValidateCredentialsRequest{
		ApiService: mockUserAPI,
	}).Once()

	mockUserAPI.On("ValidateCredentialsExecute", mock.Anything).Return(
		getToken(), nil, nil).Once()

	authSource := NewUsernamePasswordSource("user", "password", mockClient, logrus.NewEntry(logrus.New()))

	mockTeamAPI.On("GetTeams", mock.Anything).Return(client.ApiGetTeamsRequest{
		ApiService: mockTeamAPI,
	}).Once()

	teamName := "teamName"
	mockTeamAPI.On("GetTeamsExecute", mock.Anything).Return(
		[]client.Team{{Name: &teamName, ApiKeys: []client.ApiKey{
			{
				Key: "key",
			},
		}}},
		nil,
		nil,
	).Once()

	apiSource := NewApiKeySource("teamName", authSource, mockClient, logrus.NewEntry(logrus.New()))

	ctx := context.Background()
	teamsCtx, err := apiSource.ContextHeaders(ctx)
	assert.NoError(t, err)
	fmt.Println(teamsCtx)

	mockUserAPI.AssertExpectations(t)
	mockTeamAPI.AssertExpectations(t)
}

func TestApiKeySource_TeamNotExists(t *testing.T) {
	mockUserAPI := new(client.MockUserAPI)
	mockTeamAPI := new(client.MockTeamAPI)

	mockClient := &client.APIClient{
		UserAPI: mockUserAPI,
		TeamAPI: mockTeamAPI,
	}

	mockUserAPI.On("ValidateCredentials", mock.Anything).Return(client.ApiValidateCredentialsRequest{
		ApiService: mockUserAPI,
	}).Once()

	mockUserAPI.On("ValidateCredentialsExecute", mock.Anything).Return(
		getToken(), nil, nil).Once()
	mockTeamAPI.On("GetTeams", mock.Anything).Return(client.ApiGetTeamsRequest{
		ApiService: mockTeamAPI,
	}).Once()

	authSource := NewUsernamePasswordSource("user", "password", mockClient, logrus.NewEntry(logrus.New()))

	teamName := "teamName"
	mockTeamAPI.On("GetTeamsExecute", mock.Anything).Return(
		[]client.Team{{Name: &teamName, ApiKeys: []client.ApiKey{
			{
				Key: "key",
			},
		}}},
		nil,
		nil,
	).Once()

	ctx := context.Background()
	apiSource := NewApiKeySource("teamName2", authSource, mockClient, logrus.NewEntry(logrus.New()))
	_, err := apiSource.ContextHeaders(ctx)
	assert.Error(t, err)
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

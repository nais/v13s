package auth

import (
	"context"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nais/v13s/internal/sources/dependencytrack/client"
	"github.com/sirupsen/logrus"
	"sync"
	"time"
)

const XApiKeyName = "X-Api-Key"

var (
	_ Auth = &usernamePasswordSource{}
	_ Auth = &apiKeySource{}
)

type Auth interface {
	ContextHeaders(ctx context.Context) (context.Context, error)
}

type (
	Username = string
	Password = string
	Team     = string
)

type usernamePasswordSource struct {
	username    string
	password    string
	accessToken string
	lock        sync.Mutex
	client      *client.APIClient
	log         *logrus.Entry
}

func NewUsernamePasswordSource(username Username, password Password, c *client.APIClient, log *logrus.Entry) Auth {
	return &usernamePasswordSource{
		username: username,
		password: password,
		client:   c,
		log:      log,
	}
}

func (c *usernamePasswordSource) ContextHeaders(ctx context.Context) (context.Context, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	t, expired, err := c.checkAccessToken()
	if err != nil {
		return nil, err
	}

	if expired {
		t, err = c.login(ctx)
		if err != nil {
			return nil, err
		}
		c.accessToken = t
	} else {
		c.accessToken = t
	}

	return context.WithValue(ctx, client.ContextAccessToken, c.accessToken), nil
}

func (c *usernamePasswordSource) checkAccessToken() (string, bool, error) {
	if c.accessToken == "" {
		return "", true, nil
	}

	token, err := jwt.ParseString(c.accessToken, jwt.WithVerify(false))
	if err != nil {
		return "", false, fmt.Errorf("parsing accessToken: %w", err)
	}
	return c.accessToken, token.Expiration().Before(time.Now().Add(-1 * time.Minute)), nil
}

func (c *usernamePasswordSource) login(ctx context.Context) (string, error) {
	res, resp, err := c.client.UserAPI.ValidateCredentials(ctx).
		Username(c.username).
		Password(c.password).
		Execute()
	if err != nil {
		c.log.Errorf("failed to validate credentials: %v", resp)
		return "", fmt.Errorf("failed to validate credentials: %w", err)
	}

	_, err = c.parseToken(res)
	if err != nil {
		return "", fmt.Errorf("could not parse token from body after login request: %w, response body: %s", err, res)
	}

	return res, nil
}

func (c *usernamePasswordSource) parseToken(token string) (jwt.Token, error) {
	return jwt.ParseString(token, jwt.WithVerify(false))
}

type apiKeySource struct {
	team     string
	apiKey   string
	teamUuid string
	source   Auth
	client   *client.APIClient
	lock     sync.Mutex
	log      *logrus.Entry
}

func NewApiKeySource(team Team, u Auth, c *client.APIClient, log *logrus.Entry) Auth {
	return &apiKeySource{
		team:   team,
		source: u,
		client: c,
		log:    log,
	}
}

func (c *apiKeySource) ContextHeaders(ctx context.Context) (context.Context, error) {
	key, err := c.refreshApiKey(ctx)
	if err != nil {
		return nil, err
	}
	apiKey := map[string]client.APIKey{XApiKeyName: {Key: key}}
	return context.WithValue(ctx, client.ContextAPIKeys, apiKey), nil
}

func (c *apiKeySource) refreshApiKey(ctx context.Context) (string, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.apiKey == "" {
		c.log.Info("API key refreshed")
		key, err := c.getApiKey(ctx)
		if err != nil {
			return "", err
		}
		c.apiKey = key
	}
	return c.apiKey, nil
}

func (c *apiKeySource) getApiKey(ctx context.Context) (string, error) {
	bearerCtx, err := c.source.ContextHeaders(ctx)
	if err != nil {
		return "", err
	}

	if c.teamUuid == "" {
		return c.fetchTeamApiKey(bearerCtx)
	}
	return c.fetchTeamApiKeyByUuid(bearerCtx)
}

func (c *apiKeySource) fetchTeamApiKey(ctx context.Context) (string, error) {
	teams, _, err := c.client.TeamAPI.GetTeams(ctx).Execute()
	if err != nil {
		return "", fmt.Errorf("failed to get teams: %w", err)
	}

	for _, t := range teams {
		if *t.Name == c.team {
			return c.selectApiKeyFromTeam(t)
		}
	}

	return "", fmt.Errorf("no team found with name %s", c.team)
}

func (c *apiKeySource) fetchTeamApiKeyByUuid(ctx context.Context) (string, error) {
	team, _, err := c.client.TeamAPI.GetTeam(ctx, c.teamUuid).Execute()
	if err != nil {
		return "", fmt.Errorf("failed to get team: %w", err)
	}
	if team == nil {
		return "", fmt.Errorf("team with uuid %s not found", c.teamUuid)
	}
	return c.selectApiKeyFromTeam(*team)
}

func (c *apiKeySource) selectApiKeyFromTeam(t client.Team) (string, error) {
	if len(t.ApiKeys) == 0 {
		return "", fmt.Errorf("no API keys found for team %s", c.team)
	}
	c.teamUuid = t.Uuid
	return t.ApiKeys[0].Key, nil
}

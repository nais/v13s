package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources/dependencytrack/client"
	"github.com/sirupsen/logrus"
)

const ApiKeyAuthName = "ApiKeyAuth"

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
	username    Username
	password    Password
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
	db       *sql.Queries
	team     Team
	apiKey   *string
	teamUuid string
	source   Auth
	client   *client.APIClient
	lock     sync.Mutex
	log      *logrus.Entry
}

func NewApiKeySource(team Team, u Auth, c *client.APIClient, pool *pgxpool.Pool, log *logrus.Entry) Auth {
	db := sql.New(pool)
	return &apiKeySource{
		team:   team,
		source: u,
		client: c,
		db:     db,
		log:    log,
	}
}

func (c *apiKeySource) ContextHeaders(ctx context.Context) (context.Context, error) {
	key, err := c.refreshApiKey(ctx)
	if err != nil {
		return nil, err
	}
	apiKey := map[string]client.APIKey{ApiKeyAuthName: {Key: *key}}
	return context.WithValue(ctx, client.ContextAPIKeys, apiKey), nil
}

func (c *apiKeySource) refreshApiKey(ctx context.Context) (*string, error) {
	if c.apiKey != nil && *c.apiKey != "" {
		return c.apiKey, nil
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	if c.apiKey == nil {
		key, err := c.getApiKey(ctx)
		if err != nil {
			return nil, err
		}
		c.log.Info("API key refreshed")
		c.apiKey = key
	}
	return c.apiKey, nil
}

func (c *apiKeySource) getApiKey(ctx context.Context) (*string, error) {
	bearerCtx, err := c.source.ContextHeaders(ctx)
	if err != nil {
		return nil, err
	}

	if c.teamUuid != "" {
		return c.fetchTeamApiKeyByUuid(bearerCtx)
	}
	return c.fetchTeamApiKey(bearerCtx)
}

func (c *apiKeySource) fetchTeamApiKey(ctx context.Context) (*string, error) {
	teams, _, err := c.client.TeamAPI.GetTeams(ctx).Execute()
	if err != nil {
		return nil, fmt.Errorf("failed to get teams: %w", err)
	}

	for _, t := range teams {
		if *t.Name == c.team {
			return c.selectApiKeyFromTeam(ctx, t)
		}
	}

	return nil, fmt.Errorf("no team found with name %s", c.team)
}

func (c *apiKeySource) fetchTeamApiKeyByUuid(ctx context.Context) (*string, error) {
	team, _, err := c.client.TeamAPI.GetTeam(ctx, c.teamUuid).Execute()
	if err != nil {
		return nil, fmt.Errorf("failed to get team: %w", err)
	}
	if team == nil || team.Uuid == "" {
		return nil, fmt.Errorf("team with uuid %s not found", c.teamUuid)
	}
	return c.selectApiKeyFromTeam(ctx, *team)
}

func (c *apiKeySource) selectApiKeyFromTeam(ctx context.Context, t client.Team) (*string, error) {
	// Try to get existing key from DB
	sourceKey, err := c.db.GetSourceKey(ctx, t.Uuid)
	if err == nil {
		c.apiKey = &sourceKey.Key
		c.log.Infof("loaded API key for team %s from DB", *t.Name)
		return c.apiKey, nil
	}

	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("failed to query API key for team %s: %w", *t.Name, err)
	}

	// Not found in DB: generate a new one
	apikey, resp, err := c.client.TeamAPI.GenerateApiKey(ctx, t.Uuid).Execute()
	if err != nil {
		c.log.Errorf("failed to generate API key for team %s: %v: %v", *t.Name, err, resp)
		return nil, fmt.Errorf("failed to generate API key for team %s: %w", *t.Name, err)
	}

	c.apiKey = apikey.Key
	if c.apiKey == nil {
		return nil, fmt.Errorf("received nil API key from dependency-track for team %s", *t.Name)
	}

	if err = c.db.CreateSourceKey(ctx, sql.CreateSourceKeyParams{
		Name: *t.Name,
		Uuid: t.Uuid,
		Key:  *c.apiKey,
	}); err != nil {
		return nil, fmt.Errorf("failed to persist API key for team %s: %w", *t.Name, err)
	}

	c.log.Infof("Generated and persisted API key for team %s", *t.Name)
	c.teamUuid = t.Uuid
	return c.apiKey, nil
}

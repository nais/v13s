package auth

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nais/v13s/internal/sources/dependencytrack/client"
	"github.com/sirupsen/logrus"
)

var (
	_ Auth = &usernamePasswordSource{}
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

	c.log.Info("Successfully logged in with username and password")
	return res, nil
}

func (c *usernamePasswordSource) parseToken(token string) (jwt.Token, error) {
	return jwt.ParseString(token, jwt.WithVerify(false))
}

package auth

import (
	"context"
	"errors"
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

func newUsernamePasswordSourceWithToken(username Username, password Password, token string, c *client.APIClient, log *logrus.Entry) *usernamePasswordSource {
	return &usernamePasswordSource{
		username:    username,
		password:    password,
		accessToken: token,
		client:      c,
		log:         log,
	}
}

func (ups *usernamePasswordSource) ContextHeaders(ctx context.Context) (context.Context, error) {
	ups.lock.Lock()
	defer ups.lock.Unlock()

	t, expired, err := ups.checkAccessToken()
	if err != nil {
		return nil, err
	}

	if expired {
		t, err = ups.login(ctx)
		if err != nil {
			return nil, err
		}
		ups.accessToken = t
	}

	return context.WithValue(ctx, client.ContextAccessToken, ups.accessToken), nil
}

func (ups *usernamePasswordSource) checkAccessToken() (string, bool, error) {
	if ups.accessToken == "" {
		return "", true, nil
	}

	token, err := jwt.ParseString(ups.accessToken, jwt.WithVerify(false))
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired()) {
			ups.log.Debug("access token is expired, will re-login")
			return "", true, nil
		}
		return "", true, fmt.Errorf("checkAccessToken: failed to parse access token: %w", err)
	}
	expired := token.Expiration().Before(time.Now().Add(1 * time.Minute))
	return ups.accessToken, expired, nil
}

func (ups *usernamePasswordSource) login(ctx context.Context) (string, error) {
	res, resp, err := ups.client.UserAPI.ValidateCredentials(ctx).
		Username(ups.username).
		Password(ups.password).
		Execute()
	if err != nil {
		ups.log.Errorf("failed to validate credentials: %v", resp)
		return "", fmt.Errorf("failed to validate credentials: %w", err)
	}

	_, err = jwt.ParseString(res, jwt.WithVerify(false))
	if err != nil {
		return "", fmt.Errorf("could not parse token from body after login request: %w (response body: %s)", err, res)
	}

	ups.log.Info("Successfully logged in with username and password")
	return res, nil
}

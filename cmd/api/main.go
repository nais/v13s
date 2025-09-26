package main

import (
	"context"
	"os"

	"github.com/nais/v13s/internal/api"
	"github.com/nais/v13s/internal/config"
	"github.com/nais/v13s/internal/logger"
	"github.com/sirupsen/logrus"
)

const (
	exitCodeSuccess = iota
	exitCodeLoggerError
	exitCodeRunError
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log := logrus.StandardLogger()

	cfg, err := config.NewConfig()
	if err != nil {
		log.WithError(err).Errorf("error when processing configuration")
		os.Exit(exitCodeRunError)
	}

	appLogger := setupLogger(log, cfg.LogFormat, cfg.LogLevel)
	err = api.Run(ctx, cfg, appLogger)
	if err != nil {
		appLogger.WithError(err).Errorf("error in run()")
		os.Exit(exitCodeRunError)
	}

	os.Exit(exitCodeSuccess)
}

func setupLogger(log *logrus.Logger, logFormat, logLevel string) logrus.FieldLogger {
	appLogger, err := logger.New(logFormat, logLevel)
	if err != nil {
		log.WithError(err).Errorf("error when creating application logger")
		os.Exit(exitCodeLoggerError)
	}

	return appLogger
}

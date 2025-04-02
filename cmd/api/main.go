package main

import (
	"context"
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"

	"github.com/nais/v13s/internal/api"
	"github.com/nais/v13s/internal/logger"
)

const (
	exitCodeSuccess = iota
	exitCodeLoggerError
	exitCodeRunError
)

// handle env vars better
func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log := logrus.StandardLogger()

	err := godotenv.Load()
	if err != nil {
		fmt.Println("No .env file found")
	}

	var c api.Config
	err = envconfig.Process("V13S", &c)
	if err != nil {
		log.WithError(err).Errorf("error when processing configuration")
	}

	appLogger := setupLogger(log, c.LogFormat, c.LogLevel)
	err = api.Run(ctx, c, appLogger)
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

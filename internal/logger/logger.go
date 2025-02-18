package logger

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

func New(format, level string) (logrus.FieldLogger, error) {
	log := logrus.StandardLogger()

	switch strings.ToLower(format) {
	case "json":
		log.SetFormatter(&logrus.JSONFormatter{})
	case "text":
		log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	default:
		return nil, fmt.Errorf("invalid log format: %q", format)
	}

	parsedLevel, err := logrus.ParseLevel(level)
	if err != nil {
		return nil, err
	}

	log.SetLevel(parsedLevel)

	return log, nil
}

package config

import (
	"errors"
	"regexp"
)

type ExplanationConfig struct {
	Visible         bool   `envconfig:"CVE_EXPLANATIONS_VISIBLE" default:"false"`
	Project         string `envconfig:"LLM_VERTEX_PROJECT"`
	Region          string `envconfig:"LLM_VERTEX_REGION"`
	Model           string `envconfig:"LLM_MODEL"`
	MaxOutputTokens int32  `envconfig:"LLM_MAX_OUTPUT_TOKENS" default:"400"`
	MaxPerRun       int32  `envconfig:"UPDATER_EXPLAIN_CVES_MAX_PER_RUN" default:"200"`
	Concurrency     int    `envconfig:"UPDATER_EXPLAIN_CVES_CONCURRENCY" default:"2"`
}

var (
	vertexProjectPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	vertexRegionPattern  = regexp.MustCompile(`^europe-(west(1|3|4|8|9|10|12)|north(1|2)|central2|southwest1)$`)
	vertexModelPattern   = regexp.MustCompile(`^gemini-[a-z0-9][a-z0-9.-]*$`)
)

func (c ExplanationConfig) Validate(enabled bool) error {
	if !enabled {
		return nil
	}
	if !vertexProjectPattern.MatchString(c.Project) || !vertexRegionPattern.MatchString(c.Region) ||
		!vertexModelPattern.MatchString(c.Model) {
		return errors.New("CVE explanations require a Vertex project, an EU regional endpoint and a Gemini model ID")
	}
	if c.MaxPerRun < 1 || c.MaxPerRun > 10000 || c.Concurrency < 1 || c.Concurrency > 10 ||
		c.MaxOutputTokens < 1 || c.MaxOutputTokens > 2000 {
		return errors.New("CVE explanation call, concurrency or token limit is out of range")
	}
	return nil
}

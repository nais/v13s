package model

type EventToken struct {
	ProjectId string
	ImageName string
	ImageTag  string
	Token     string
}

type EventTokens []*EventToken

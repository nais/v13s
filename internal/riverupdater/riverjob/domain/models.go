package domain

type AnalysisTokenInfo struct {
	ImageName    string
	ImageTag     string
	ProjectID    string
	ProcessToken string
}

type Image struct {
	Name string
	Tag  string
}

package typeext

type MapStringString map[string]string

type Cwe struct {
	Id   int32  `json:"id"`
	Name string `json:"name"`
	Link string `json:"link"`
}

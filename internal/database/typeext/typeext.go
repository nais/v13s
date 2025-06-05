package typeext

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

type MapStringString map[string]string

func (m *MapStringString) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("type assertion to []byte failed")
	}
	return json.Unmarshal(bytes, m)
}

func (m *MapStringString) Value() (driver.Value, error) {
	return json.Marshal(m)
}

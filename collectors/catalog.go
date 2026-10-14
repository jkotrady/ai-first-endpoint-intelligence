// Package collectors shares the implemented allowlist between API and build tooling.
package collectors

import (
	"embed"
	"encoding/json"
)

//go:embed catalog.json
var files embed.FS

type Entry struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Source      string `json:"source"`
	Entrypoint  string `json:"entrypoint"`
	Limitations string `json:"limitations"`
}

var entries = func() []Entry {
	data, err := files.ReadFile("catalog.json")
	if err != nil {
		panic(err)
	}
	var list []Entry
	if err = json.Unmarshal(data, &list); err != nil {
		panic(err)
	}
	return list
}()

func All() []Entry { return append([]Entry{}, entries...) }
func IDs() []string {
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		ids = append(ids, e.ID)
	}
	return ids
}
func Allowed(id string) bool {
	for _, e := range entries {
		if e.ID == id {
			return true
		}
	}
	return false
}

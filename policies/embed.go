package policies

import (
	"embed"
)

//go:embed *.cedar
var FS embed.FS

// Base returns the compiled-in Cedar policy bundle.
func Base() (string, error) {
	b, err := FS.ReadFile("base.cedar")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

package httpserver

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.json
var openAPIDocument []byte

func (a *App) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	// Spec-first document; authenticated users only once sessions are required.
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(openAPIDocument)
}

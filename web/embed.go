package web

import "embed"

// TemplateFS holds html/template sources (CSP-safe; no inline scripts).
//
//go:embed templates/*.tmpl
var TemplateFS embed.FS

// StaticFS holds first-party CSS and ES modules.
//
//go:embed static/*
var StaticFS embed.FS

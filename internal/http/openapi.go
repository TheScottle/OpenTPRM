package httpserver

// Minimal OpenAPI 3.1 document (expanded through M5).
var openAPIDocument = []byte(`{
  "openapi": "3.1.0",
  "info": {"title": "OpenTPRM API", "version": "1.0.0"},
  "paths": {
    "/health/live": {"get": {"summary": "Liveness", "responses": {"200": {"description": "ok"}}}},
    "/health/ready": {"get": {"summary": "Readiness", "responses": {"200": {"description": "ready"}, "503": {"description": "sealed"}}}},
    "/api/v1/vendors": {"get": {"summary": "List vendors"}, "post": {"summary": "Create vendor"}},
    "/api/v1/intakes": {"post": {"summary": "Create intake"}},
    "/api/v1/intakes/{id}:submit": {"post": {"summary": "Submit intake and compute tier"}},
    "/api/v1/assessments": {"get": {"summary": "List assessments"}, "post": {"summary": "Create assessment"}},
    "/api/v1/assessments/{id}:transition": {"post": {"summary": "Transition assessment state"}},
    "/api/v1/uploads": {"post": {"summary": "Chunked upload complete (simplified)"}},
    "/api/v1/evidence": {"get": {"summary": "List evidence"}},
    "/api/v1/findings": {"get": {"summary": "List findings"}},
    "/api/v1/risk/compute": {"post": {"summary": "Compute residual risk"}},
    "/api/v1/exceptions/{id}:approve": {"post": {"summary": "Approve exception (humans only)"}},
    "/api/v1/audit/verify": {"post": {"summary": "Verify audit chain"}},
    "/api/v1/agent/tools": {"get": {"summary": "Agent tool registry (OpenAI format)"}},
    "/api/v1/change-requests": {"get": {"summary": "List change requests"}},
    "/api/v1/suggestions": {"get": {"summary": "List AI suggestions"}}
  }
}`)

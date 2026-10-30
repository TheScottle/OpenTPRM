package schemas

import "embed"

// FS holds JSON Schema documents (SOC review, future tool/import schemas).
//
//go:embed *.json
var FS embed.FS

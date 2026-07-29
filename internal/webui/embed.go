package webui

import "embed"

// Files contains the production Vue application.
//
//go:embed dist
var Files embed.FS

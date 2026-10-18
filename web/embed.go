// Package web holds the RalX admin app (plain HTML, CSS and JS, no build step).
package web

import "embed"

//go:embed app
var Files embed.FS

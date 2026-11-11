// Package web embeds the SakuNet dashboard single-page app.
package web

import "embed"

//go:embed index.html
var FS embed.FS

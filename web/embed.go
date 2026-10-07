// Package web embeds the pre-built browser dashboard (web/dist).
//
// The bundle is produced by `make web` (npm ci && npm run build) and the
// generated files are committed, so `go build` never needs Node. Go embed
// directives cannot reference parent directories, which is why this package
// lives next to dist/ and cmd/webtraffik imports it.
package web

import (
	"embed"
	"io/fs"
)

//go:embed dist
var dist embed.FS

// FS serves the built dashboard rooted at dist/, so "/" resolves to
// index.html without a "dist/" segment appearing in URLs.
var FS fs.FS = mustSub()

func mustSub() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic("web embed: " + err.Error())
	}
	return sub
}

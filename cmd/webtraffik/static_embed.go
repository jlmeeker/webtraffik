package main

import (
	"embed"
	"io/fs"
)

//go:embed static
var staticFiles embed.FS

// staticSubFS strips the "static/" prefix so the HTTP file-server can serve
// / → index.html without the "static/" segment appearing in every URL.
func staticSubFS() fs.FS {
	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic("static embed: " + err.Error())
	}
	return sub
}

package main

import (
	"io/fs"

	"webtraffik/web"
)

// staticSubFS returns the embedded browser dashboard (built from web/ into
// web/dist by `make web`) rooted so that "/" serves index.html.
func staticSubFS() fs.FS {
	return web.FS
}

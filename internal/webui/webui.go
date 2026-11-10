// Package webui serves the web UI built into the control plane binary. The
// UI is built by `atmos web build` into dist/app; dist/.gitkeep keeps the
// embed compiling when it has not been built.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var dist embed.FS

// Handler serves the embedded UI.
func Handler() http.Handler {
	app, err := fs.Sub(dist, "dist/app")
	if err != nil {
		return handler(nil)
	}
	return handler(app)
}

// handler serves files from app. Paths that are not files get index.html so
// the client-side router can handle them, except under assets/, where a
// missing file is a 404 rather than a page.
func handler(app fs.FS) http.Handler {
	var index []byte
	if app != nil {
		index, _ = fs.ReadFile(app, "index.html")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name != "" && name != "index.html" && app != nil {
			if info, err := fs.Stat(app, name); err == nil && !info.IsDir() {
				if strings.HasPrefix(name, "assets/") {
					// file names carry a content hash
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				} else {
					w.Header().Set("Cache-Control", "no-cache")
				}
				http.ServeFileFS(w, r, app, name)
				return
			}
		}
		if strings.HasPrefix(name, "assets/") {
			http.NotFound(w, r)
			return
		}
		if index == nil {
			http.Error(w, "the web UI is not built into this binary (run `atmos web build`)", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(index)
	})
}

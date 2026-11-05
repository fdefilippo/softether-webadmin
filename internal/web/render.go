package web

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed assets
var assetsFS embed.FS

// StaticFS is the embedded static asset tree (htmx, CSS), to be served under
// /static/. Templates and catalogs are not reachable through it.
func StaticFS() fs.FS {
	sub, err := fs.Sub(assetsFS, "assets/static")
	if err != nil {
		panic(err) // the path is a compile-time constant of the embed
	}
	return sub
}

// EmbeddedCatalogs loads the embedded i18n catalogs.
func EmbeddedCatalogs() (Catalog, error) {
	sub, err := fs.Sub(assetsFS, "assets/i18n")
	if err != nil {
		return nil, err
	}
	return LoadCatalogs(sub)
}

// EmbeddedTemplates is the embedded template tree: layout.html plus one file
// per page.
func EmbeddedTemplates() fs.FS {
	sub, err := fs.Sub(assetsFS, "assets/templates")
	if err != nil {
		panic(err)
	}
	return sub
}

// View is what every page template receives as ".".
type View struct {
	Lang    string
	Session *Session // nil on pages shown without a session
	Next    string   // current request URI, used by the language selector
	Data    any      // page-specific data passed to Renderer.Page
	cat     Catalog
}

// T translates key into the page language (see Catalog.T).
func (v View) T(key string, args ...any) string { return v.cat.T(v.Lang, key, args...) }

// CSRF is the session's CSRF token, or "" without a session.
func (v View) CSRF() string {
	if v.Session == nil {
		return ""
	}
	return v.Session.CSRF
}

// HXHeaders is the JSON for the hx-headers attribute of <body>: it makes
// htmx send the CSRF token with every request. Empty without a session.
func (v View) HXHeaders() string {
	if v.Session == nil {
		return ""
	}
	b, _ := json.Marshal(map[string]string{"X-CSRF-Token": v.Session.CSRF})
	return string(b)
}

// Renderer renders pages inside the shared layout.
type Renderer struct {
	cat   Catalog
	pages map[string]*template.Template
}

// NewRenderer parses templates/: layout.html defines the page frame and calls
// {{template "content" .}}; every other *.html file defines "content" and is
// addressed by its base name without extension.
func NewRenderer(cat Catalog, templates fs.FS) (Renderer, error) {
	layout, err := fs.ReadFile(templates, "layout.html")
	if err != nil {
		return Renderer{}, fmt.Errorf("render: %w", err)
	}
	files, err := fs.Glob(templates, "*.html")
	if err != nil {
		return Renderer{}, err
	}
	r := Renderer{cat: cat, pages: map[string]*template.Template{}}
	for _, f := range files {
		if f == "layout.html" {
			continue
		}
		src, err := fs.ReadFile(templates, f)
		if err != nil {
			return Renderer{}, err
		}
		name := strings.TrimSuffix(path.Base(f), ".html")
		t, err := template.New(name).Parse(string(layout))
		if err != nil {
			return Renderer{}, fmt.Errorf("render: layout: %w", err)
		}
		if _, err := t.Parse(string(src)); err != nil {
			return Renderer{}, fmt.Errorf("render: %s: %w", f, err)
		}
		r.pages[name] = t
	}
	return r, nil
}

// Page renders the named page inside the layout. The session, if any, is the
// one RequireSession stored in the request context: pages behind
// RequireSession get hx-headers and the logout form; the login page, outside
// it, gets neither. The page is rendered to a buffer first, so a template
// error yields a clean 500 instead of a half-written page.
func (r Renderer) Page(w http.ResponseWriter, req *http.Request, name string, data any) {
	t, ok := r.pages[name]
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s, _ := SessionFrom(req.Context())
	v := View{Lang: Negotiate(req), Session: s, Next: req.URL.RequestURI(), Data: data, cat: r.cat}
	var buf bytes.Buffer
	if err := t.Execute(&buf, v); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

package web

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
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
	PreCSRF string   // pre-session CSRF token for forms outside RequireSession
	cat     Catalog
}

// T translates key into the page language (see Catalog.T).
func (v View) T(key string, args ...any) string { return v.cat.T(v.Lang, key, args...) }

// CSRF is the token to put in the "csrf" field of a form: the session's, or
// on pages shown without a session the pre-session token (see preCSRF).
func (v View) CSRF() string {
	if v.Session == nil {
		return v.PreCSRF
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
	log   *slog.Logger
}

// WithLogger returns a Renderer that logs template errors (page name and
// error text, never the page data) to l.
func (r Renderer) WithLogger(l *slog.Logger) Renderer {
	r.log = l
	return r
}

func (r Renderer) logError(page string, err error) {
	l := r.log
	if l == nil {
		l = slog.Default()
	}
	l.Error("template error", "page", page, "err", err.Error())
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

// Page renders the named page inside the layout with status 200; see
// PageStatus.
func (r Renderer) Page(w http.ResponseWriter, req *http.Request, name string, data any) {
	r.PageStatus(w, req, http.StatusOK, name, data)
}

func (r Renderer) view(req *http.Request, data any) View {
	s, _ := SessionFrom(req.Context())
	pre, _ := req.Context().Value(preCSRFKey{}).(string)
	return View{Lang: Negotiate(req), Session: s, Next: req.URL.RequestURI(), Data: data, PreCSRF: pre, cat: r.cat}
}

// PageStatus renders the named page inside the layout. The session, if any,
// is the one RequireSession (or the optional-session wrapper) stored in the
// request context: pages with a session get hx-headers and the logout form.
// The page is rendered to a buffer first, so a template error yields a clean
// 500 (and a log line) instead of a half-written page. The language is
// always Negotiate(req).
func (r Renderer) PageStatus(w http.ResponseWriter, req *http.Request, code int, name string, data any) {
	t, ok := r.pages[name]
	if !ok {
		r.logError(name, errors.New("unknown page"))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, r.view(req, data)); err != nil {
		r.logError(name, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write(buf.Bytes())
}

// Fragment renders only the "content" template of the named page, without the
// layout: the body of an htmx response.
func (r Renderer) Fragment(w http.ResponseWriter, req *http.Request, name string, data any) {
	t, ok := r.pages[name]
	if !ok {
		r.logError(name, errors.New("unknown page"))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "content", r.view(req, data)); err != nil {
		r.logError(name, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

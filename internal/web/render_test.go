package web

import (
	"bytes"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/fdefilippo/softether-webadmin/internal/rpc"
)

func testRenderer(t *testing.T) Renderer {
	t.Helper()
	layout, err := fs.ReadFile(assetsFS, "assets/templates/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	tpls := fstest.MapFS{
		"layout.html": {Data: layout},
		"test.html":   {Data: []byte(`{{define "content"}}<p id="c">{{.Data}}</p>{{end}}`)},
	}
	sub, _ := fs.Sub(assetsFS, "assets/i18n")
	cat, err := LoadCatalogs(sub)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRenderer(cat, tpls)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRenderAnonymousPage(t *testing.T) {
	r := testRenderer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/login", nil)
	req.Header.Set("Accept-Language", "it")
	r.Page(rec, req, "test", "<b>x</b>")
	body := rec.Body.String()

	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("code=%d ct=%q", rec.Code, rec.Header().Get("Content-Type"))
	}
	for _, want := range []string{
		`<html lang="it">`,
		`<meta name="htmx-config" content='{"allowEval":false,"allowScriptTags":false,"historyCacheSize":0,"refreshOnHistoryMiss":true,"includeIndicatorStyles":false,"selfRequestsOnly":true}'>`,
		`<script src="/static/htmx.min.js"></script>`,
		`href="/static/app.css"`,
		`/lang?l=en`, `/lang?l=it`,
		`<p id="c">&lt;b&gt;x&lt;/b&gt;</p>`, // data is escaped
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q\n%s", want, body)
		}
	}
	if strings.Contains(body, "hx-headers") || strings.Contains(body, `action="/logout"`) {
		t.Errorf("anonymous page must have no hx-headers and no logout form:\n%s", body)
	}
	if strings.Contains(body, "!") && regexp.MustCompile(`![a-z.]+!`).MatchString(body) {
		t.Errorf("missing catalog key in layout:\n%s", body)
	}
}

func TestRenderCSPCompatible(t *testing.T) {
	r := testRenderer(t)
	st := NewSessionStore(time.Minute, time.Hour, newClock().Now)
	s := st.Create(rpc.Credential{}, "en")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil).WithContext(withSession(httptest.NewRequest("GET", "/", nil).Context(), s))
	r.Page(rec, req, "test", "x")
	body := rec.Body.String()

	if m := regexp.MustCompile(`(?is)<script\b[^>]*>`).FindAllString(body, -1); len(m) != 1 || !strings.Contains(m[0], `src="/static/htmx.min.js"`) {
		t.Errorf("only the external htmx script is allowed, got %v", m)
	}
	if regexp.MustCompile(`(?is)<script[^>]*>[^<]`).MatchString(body) {
		t.Error("inline script content")
	}
	if regexp.MustCompile(`(?is)<style\b`).MatchString(body) {
		t.Error("inline <style>")
	}
	if regexp.MustCompile(`(?is)<[^>]+\sstyle\s*=`).MatchString(body) {
		t.Error("inline style attribute")
	}
	if regexp.MustCompile(`(?is)<[^>]+\son[a-z]+\s*=`).MatchString(body) {
		t.Error("inline on* event handler")
	}
	if strings.Contains(body, "javascript:") {
		t.Error("javascript: URL")
	}
}

func TestRenderAuthenticatedPage(t *testing.T) {
	r := testRenderer(t)
	st := NewSessionStore(time.Minute, time.Hour, newClock().Now)
	s := st.Create(rpc.Credential{Password: "topsecret"}, "en")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req = req.WithContext(withSession(req.Context(), s))
	r.Page(rec, req, "test", "x")
	body := rec.Body.String()

	// html/template escapes the quotes of the attribute value as &#34;.
	wantHdr := `hx-headers='{&#34;X-CSRF-Token&#34;:&#34;` + s.CSRF + `&#34;}'`
	if !strings.Contains(body, wantHdr) {
		t.Errorf("missing %s in\n%s", wantHdr, body)
	}
	if !strings.Contains(body, `action="/logout"`) || !strings.Contains(body, `name="csrf" value="`+s.CSRF+`"`) {
		t.Errorf("missing logout form with csrf field:\n%s", body)
	}
	if strings.Contains(body, "topsecret") || strings.Contains(body, s.ID) {
		t.Error("page leaks credentials or session id")
	}
}

func TestRenderUnknownPage(t *testing.T) {
	r := testRenderer(t)
	rec := httptest.NewRecorder()
	r.Page(rec, httptest.NewRequest("GET", "/", nil), "nope", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500", rec.Code)
	}
}

func TestEmbeddedAssets(t *testing.T) {
	for _, p := range []string{"assets/static/htmx.min.js", "assets/static/app.css", "assets/templates/layout.html", "assets/i18n/en.json", "assets/i18n/it.json"} {
		if _, err := fs.Stat(assetsFS, p); err != nil {
			t.Errorf("missing embedded asset %s: %v", p, err)
		}
	}
	if _, err := fs.Stat(StaticFS(), "htmx.min.js"); err != nil {
		t.Errorf("StaticFS must serve htmx.min.js: %v", err)
	}
	if _, err := fs.Stat(StaticFS(), "layout.html"); err == nil {
		t.Error("templates must not be reachable through StaticFS")
	}
}

func TestRenderLogsTemplateErrorWithoutData(t *testing.T) {
	var logs bytes.Buffer
	layout, _ := fs.ReadFile(assetsFS, "assets/templates/layout.html")
	tpls := fstest.MapFS{
		"layout.html": {Data: layout},
		"bad.html":    {Data: []byte(`{{define "content"}}{{index .Data 5}}{{end}}`)},
	}
	sub, _ := fs.Sub(assetsFS, "assets/i18n")
	cat, _ := LoadCatalogs(sub)
	r, err := NewRenderer(cat, tpls)
	if err != nil {
		t.Fatal(err)
	}
	r = r.WithLogger(slog.New(slog.NewTextHandler(&logs, nil)))

	rec := httptest.NewRecorder()
	r.Page(rec, httptest.NewRequest("GET", "/x", nil), "bad", []string{"s3cret-value"})
	if rec.Code != 500 {
		t.Fatalf("code = %d, want 500", rec.Code)
	}
	if !strings.Contains(logs.String(), "bad") || strings.Contains(logs.String(), "s3cret-value") {
		t.Fatalf("log must name the page and not contain data: %s", logs.String())
	}
}

func TestRenderFragmentHasNoLayout(t *testing.T) {
	r := testRenderer(t)
	rec := httptest.NewRecorder()
	r.Fragment(rec, httptest.NewRequest("GET", "/status", nil), "test", "hi")
	body := rec.Body.String()
	if !strings.Contains(body, `<p id="c">hi</p>`) || strings.Contains(body, "<html") {
		t.Fatalf("fragment = %s", body)
	}
}

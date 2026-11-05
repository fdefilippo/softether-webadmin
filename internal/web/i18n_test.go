package web

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
)

func TestCatalogsSameKeys(t *testing.T) {
	sub, err := fs.Sub(assetsFS, "assets/i18n")
	if err != nil {
		t.Fatal(err)
	}
	cat, err := LoadCatalogs(sub)
	if err != nil {
		t.Fatal(err)
	}
	en, it := cat["en"], cat["it"]
	if len(en) == 0 || len(it) == 0 {
		t.Fatalf("empty catalog: en=%d it=%d", len(en), len(it))
	}
	keys := func(m map[string]string) []string {
		var ks []string
		for k := range m {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		return ks
	}
	if a, b := keys(en), keys(it); strings.Join(a, ",") != strings.Join(b, ",") {
		t.Fatalf("key sets differ:\n en=%v\n it=%v", a, b)
	}
	for k, v := range it {
		if v == "" || en[k] == "" {
			t.Errorf("empty value for %q", k)
		}
	}
}

func TestCatalogT(t *testing.T) {
	cat, err := LoadCatalogs(fstest.MapFS{
		"en.json": {Data: []byte(`{"hello":"Hello %s","only.en":"English only","both":"B-en"}`)},
		"it.json": {Data: []byte(`{"hello":"Ciao %s","both":"B-it"}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		lang, key string
		args      []any
		want      string
	}{
		{"it", "hello", []any{"Mario"}, "Ciao Mario"},
		{"en", "hello", []any{"Mario"}, "Hello Mario"},
		{"it", "only.en", nil, "English only"}, // falls back to en
		{"it", "both", nil, "B-it"},
		{"fr", "both", nil, "B-en"}, // unknown language falls back to en
		{"it", "missing", nil, "!missing!"},
		{"en", "missing", nil, "!missing!"},
	} {
		if got := cat.T(c.lang, c.key, c.args...); got != c.want {
			t.Errorf("T(%q,%q) = %q, want %q", c.lang, c.key, got, c.want)
		}
	}
}

func TestLoadCatalogsErrors(t *testing.T) {
	if _, err := LoadCatalogs(fstest.MapFS{"it.json": {Data: []byte(`{}`)}}); err == nil {
		t.Error("missing en.json must be an error")
	}
	if _, err := LoadCatalogs(fstest.MapFS{"en.json": {Data: []byte(`[1]`)}}); err == nil {
		t.Error("non-object JSON must be an error")
	}
}

func TestNegotiate(t *testing.T) {
	mk := func(accept, cookie string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		if accept != "" {
			r.Header.Set("Accept-Language", accept)
		}
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: LangCookie, Value: cookie})
		}
		return r
	}
	for _, c := range []struct {
		accept, cookie, want string
	}{
		{"it-IT,it;q=0.9", "", "it"},
		{"it-IT,it;q=0.9", "en", "en"},
		{"", "", "en"},
		{"fr-FR,fr;q=0.9", "", "en"},
		{"fr,it;q=0.5,en;q=0.8", "", "en"},
		{"en;q=0.3,it;q=0.8", "", "it"},
		{"it", "xx", "it"}, // invalid cookie is ignored
		{"it;q=0", "", "en"},
	} {
		if got := Negotiate(mk(c.accept, c.cookie)); got != c.want {
			t.Errorf("Negotiate(accept=%q cookie=%q) = %q, want %q", c.accept, c.cookie, got, c.want)
		}
	}
}

func TestLangHandler(t *testing.T) {
	h := LangHandler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/lang?l=it&next=/vhubs", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/vhubs" {
		t.Fatalf("code=%d loc=%q", rec.Code, rec.Header().Get("Location"))
	}
	c := rec.Result().Cookies()[0]
	if c.Name != "swa_lang" || c.Value != "it" || !c.Secure || c.Path != "/" {
		t.Fatalf("cookie = %+v", c)
	}

	for _, next := range []string{"//evil.example", "https://evil.example", "/\\evil", ""} {
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/lang?l=en&next="+next, nil))
		if loc := rec.Header().Get("Location"); loc != "/" {
			t.Errorf("next=%q redirected to %q, want /", next, loc)
		}
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/lang?l=xx", nil))
	if rec.Code != http.StatusBadRequest || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("unsupported language: code=%d", rec.Code)
	}
}

func TestLangHandlerNextTable(t *testing.T) {
	h := LangHandler()
	for _, c := range []struct{ next, want string }{
		{"/\t/evil.example", "/"},
		{"/\v/x", "/"},
		{"/\r/evil", "/"},
		{"/\n/evil", "/"},
		{"/\x00", "/"},
		{"/\x7f", "/"},
		{"//evil", "/"},
		{"/\\evil", "/"},
		{"https://evil", "/"},
		{"evil.example", "/"},
		{"", "/"},
		{"/dashboard?x=1", "/dashboard?x=1"},
		{"/vhubs", "/vhubs"},
		{"/%09/evil", "/%09/evil"}, // literal percent-escape: stays a same-site path
	} {
		q := url.Values{"l": {"it"}, "next": {c.next}}.Encode()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/lang?"+q, nil))
		if loc := rec.Header().Get("Location"); loc != c.want {
			t.Errorf("next=%q -> Location %q, want %q", c.next, loc, c.want)
		}
	}
	// Raw query-encoded form of "/<TAB>/evil" as a browser/attacker would send it.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/lang?l=it&next=%2F%09%2Fevil.example", nil))
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Errorf("raw tab case -> %q, want /", loc)
	}
}

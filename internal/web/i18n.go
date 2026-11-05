package web

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// LangCookie is the name of the language-preference cookie.
const LangCookie = "swa_lang"

// DefaultLang is used when nothing else matches; every key must exist in it.
const DefaultLang = "en"

// Languages lists the supported UI languages.
var Languages = []string{"en", "it"}

func supported(lang string) bool {
	for _, l := range Languages {
		if l == lang {
			return true
		}
	}
	return false
}

// Catalog maps language -> key -> message (fmt.Sprintf format).
type Catalog map[string]map[string]string

// LoadCatalogs reads every <lang>.json (a flat key -> string object) from the
// root of fsys. en.json is required: it is the fallback language.
func LoadCatalogs(fsys fs.FS) (Catalog, error) {
	files, err := fs.Glob(fsys, "*.json")
	if err != nil {
		return nil, err
	}
	c := Catalog{}
	for _, f := range files {
		data, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, err
		}
		m := map[string]string{}
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("i18n %s: %w", f, err)
		}
		c[strings.TrimSuffix(path.Base(f), ".json")] = m
	}
	if _, ok := c[DefaultLang]; !ok {
		return nil, fmt.Errorf("i18n: %s.json is missing", DefaultLang)
	}
	return c, nil
}

// T returns the message for key in lang, formatted with args when given. A
// key missing in lang falls back to English; a key missing everywhere yields
// "!key!" so the gap is visible on the page.
func (c Catalog) T(lang, key string, args ...any) string {
	msg, ok := c[lang][key]
	if !ok {
		msg, ok = c[DefaultLang][key]
	}
	if !ok {
		return "!" + key + "!"
	}
	if len(args) == 0 {
		return msg
	}
	return fmt.Sprintf(msg, args...)
}

// Negotiate picks the UI language: a valid swa_lang cookie wins, then the
// highest-weighted supported Accept-Language entry, then English.
func Negotiate(r *http.Request) string {
	if c, err := r.Cookie(LangCookie); err == nil && supported(c.Value) {
		return c.Value
	}
	type cand struct {
		lang string
		q    float64
		pos  int
	}
	var cands []cand
	for i, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		tag, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		tag = strings.ToLower(strings.TrimSpace(tag))
		primary, _, _ := strings.Cut(tag, "-")
		if !supported(primary) {
			continue
		}
		q := 1.0
		if p := strings.TrimSpace(params); strings.HasPrefix(p, "q=") {
			v, err := strconv.ParseFloat(strings.TrimPrefix(p, "q="), 64)
			if err != nil {
				continue
			}
			q = v
		}
		if q > 0 {
			cands = append(cands, cand{primary, q, i})
		}
	}
	if len(cands) == 0 {
		return DefaultLang
	}
	sort.SliceStable(cands, func(a, b int) bool { return cands[a].q > cands[b].q })
	return cands[0].lang
}

// LangHandler serves /lang?l=<lang>[&next=<local path>]: it stores the choice
// in the swa_lang cookie and redirects back to next (only same-site absolute
// paths are honoured) or to /.
func LangHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang := r.URL.Query().Get("l")
		if !supported(lang) {
			http.Error(w, "unsupported language", http.StatusBadRequest)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: LangCookie, Value: lang, Path: "/", MaxAge: int((365 * 24 * time.Hour).Seconds()),
			HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
		})
		http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther)
	})
}

// safeNext returns next if it is a same-site absolute path, else "/".
func safeNext(next string) string {
	if strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//") && !strings.ContainsAny(next, "\\\r\n") {
		return next
	}
	return "/"
}

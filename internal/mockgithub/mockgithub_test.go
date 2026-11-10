package mockgithub

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAuthorize_RedirectsOnlyToRegisteredCallback(t *testing.T) {
	h := New(Options{ClientID: "cid", CallbackURLs: []string{"http://localhost:4100/api/v1/auth/callback"}, Users: DefaultUsers()}).Handler()
	get := func(redirectURI string) *httptest.ResponseRecorder {
		q := url.Values{"client_id": {"cid"}, "redirect_uri": {redirectURI}, "state": {"s"}, "login": {"alice"}}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login/oauth/authorize?"+q.Encode(), nil))
		return rec
	}
	rec := get("http://localhost:4100/api/v1/auth/callback")
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.HasPrefix(loc, "http://localhost:4100/api/v1/auth/callback?") || !strings.Contains(loc, "code=") {
		t.Fatalf("registered callback: %d %q", rec.Code, loc)
	}
	for _, evil := range []string{"https://evil.example.com/cb", "http://localhost:4100/api/v1/auth/callback/../../x", ""} {
		if rec := get(evil); rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
			t.Errorf("redirect_uri %q: %d %q", evil, rec.Code, rec.Header().Get("Location"))
		}
	}
}

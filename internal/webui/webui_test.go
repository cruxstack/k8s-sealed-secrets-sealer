package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func serve(t *testing.T, h http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

func TestHandler(t *testing.T) {
	h := handler(fstest.MapFS{
		"index.html":           {Data: []byte("<html>app</html>")},
		"favicon.svg":          {Data: []byte("<svg/>")},
		"assets/index-abc.js":  {Data: []byte("console.log(1)")},
		"assets/index-abc.css": {Data: []byte("body{}")},
	})

	cases := []struct {
		target, wantBody, wantCache string
		wantStatus                  int
	}{
		{"/", "<html>app</html>", "no-store", 200},
		{"/agents/use1-blue", "<html>app</html>", "no-store", 200}, // client-side route
		{"/index.html", "<html>app</html>", "no-store", 200},
		{"/assets/index-abc.js", "console.log(1)", "public, max-age=31536000, immutable", 200},
		{"/favicon.svg", "<svg/>", "no-cache", 200},
		{"/assets/missing.js", "", "", 404},
		{"/../../etc/passwd", "<html>app</html>", "no-store", 200},
	}
	for _, tc := range cases {
		rec := serve(t, h, http.MethodGet, tc.target)
		if rec.Code != tc.wantStatus {
			t.Errorf("%s = %d, want %d", tc.target, rec.Code, tc.wantStatus)
			continue
		}
		if tc.wantBody != "" && !strings.Contains(rec.Body.String(), tc.wantBody) {
			t.Errorf("%s body = %q", tc.target, rec.Body)
		}
		if got := rec.Header().Get("Cache-Control"); tc.wantCache != "" && got != tc.wantCache {
			t.Errorf("%s Cache-Control = %q, want %q", tc.target, got, tc.wantCache)
		}
	}
	if rec := serve(t, h, http.MethodPost, "/"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST / = %d", rec.Code)
	}
}

func TestHandler_NotBuilt(t *testing.T) {
	if rec := serve(t, handler(nil), http.MethodGet, "/"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unbuilt UI = %d", rec.Code)
	}
	// the real embed compiles and serves even before the UI is built
	if rec := serve(t, Handler(), http.MethodGet, "/assets/x.js"); rec.Code != http.StatusNotFound {
		t.Fatalf("embedded missing asset = %d", rec.Code)
	}
}

package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/testutil/testcerts"
)

func event(method, rawPath string) events.APIGatewayV2HTTPRequest {
	e := events.APIGatewayV2HTTPRequest{RawPath: rawPath, Headers: map[string]string{}}
	e.RequestContext.HTTP.Method = method
	e.RequestContext.HTTP.SourceIP = "203.0.113.7"
	e.RequestContext.DomainName = "abc123.execute-api.us-east-1.amazonaws.com"
	return e
}

func body(t *testing.T, resp events.APIGatewayV2HTTPResponse) []byte {
	t.Helper()
	if !resp.IsBase64Encoded {
		return []byte(resp.Body)
	}
	b, err := base64.StdEncoding.DecodeString(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestInvoke_PassesTheRequestAndResponseThrough(t *testing.T) {
	type request struct {
		Method, Path, RawPath, Query, Host, Remote, CSRF, Cookie, Body string
		Length                                                         int64
	}
	var seen request
	h := &handler{logger: slog.New(slog.DiscardHandler), next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen.Method, seen.Path, seen.RawPath, seen.Query = r.Method, r.URL.Path, r.URL.RawPath, r.URL.RawQuery
		seen.Host, seen.Remote, seen.CSRF = r.Host, r.RemoteAddr, r.Header.Get("X-CSRF-Token")
		seen.Cookie, seen.Body, seen.Length = r.Header.Get("Cookie"), string(b), r.ContentLength
		http.SetCookie(w, &http.Cookie{Name: "a", Value: "1"})
		http.SetCookie(w, &http.Cookie{Name: "b", Value: "2"})
		w.Header().Add("Vary", "Cookie")
		w.Header().Add("Vary", "Accept")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})}

	e := event(http.MethodPost, "/api/v1/repos/example-org/apps/files%2Fx")
	e.RawQueryString = "commit=abc&x=1"
	e.Headers = map[string]string{"host": "sealer.example.com", "x-csrf-token": "token", "content-type": "application/json"}
	e.Cookies = []string{"sealer_session=s", "other=o"}
	e.Body = base64.StdEncoding.EncodeToString([]byte(`{"value":"é"}`))
	e.IsBase64Encoded = true

	resp, err := h.invoke(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	want := request{
		Method: http.MethodPost, Path: "/api/v1/repos/example-org/apps/files/x", RawPath: "/api/v1/repos/example-org/apps/files%2Fx",
		Query: "commit=abc&x=1", Host: "sealer.example.com", Remote: "203.0.113.7:0", CSRF: "token",
		Cookie: "sealer_session=s; other=o", Body: `{"value":"é"}`, Length: 14,
	}
	if seen != want {
		t.Fatalf("request seen:\n%+v\nwant:\n%+v", seen, want)
	}
	if resp.StatusCode != http.StatusCreated || string(body(t, resp)) != `{"ok":true}` ||
		resp.Headers["Content-Type"] != "application/json" || resp.Headers["Vary"] != "Cookie, Accept" {
		t.Fatalf("response = %+v", resp)
	}
	if !slices.Equal(resp.Cookies, []string{"a=1", "b=2"}) || resp.Headers["Set-Cookie"] != "" {
		t.Fatalf("cookies = %q, headers = %v", resp.Cookies, resp.Headers)
	}
}

func TestInvoke_BinaryBodiesAndSniffing(t *testing.T) {
	png := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
	h := &handler{logger: slog.New(slog.DiscardHandler), next: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(png)
	})}
	resp, err := h.invoke(context.Background(), event(http.MethodGet, "/logo.png"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || resp.Headers["Content-Type"] != "image/png" || string(body(t, resp)) != string(png) {
		t.Fatalf("response = %+v", resp)
	}
}

func TestInvoke_Refuses(t *testing.T) {
	h := &handler{logger: slog.New(slog.DiscardHandler), next: http.NotFoundHandler()}
	if _, err := h.invoke(context.Background(), events.APIGatewayV2HTTPRequest{}); err == nil {
		t.Error("an event that is not an HTTP request was accepted")
	}
	e := event(http.MethodPost, "/x")
	e.Body, e.IsBase64Encoded = "not base64!", true
	if resp, err := h.invoke(context.Background(), e); err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad base64 = %+v, %v", resp, err)
	}
	e = event(http.MethodGet, "relative")
	if resp, _ := h.invoke(context.Background(), e); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("relative path = %+v", resp)
	}
	big := &handler{logger: slog.New(slog.DiscardHandler), next: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, maxResponseBytes+1))
	})}
	if resp, _ := big.invoke(context.Background(), event(http.MethodGet, "/")); resp.StatusCode != http.StatusBadGateway {
		t.Errorf("oversized response = %d", resp.StatusCode)
	}
}

// TestSetup_ServesTheControlPlane builds the real control plane from
// environment variables, with the registry inline, and serves it through
// the Lambda handler. Nothing here calls AWS or GitHub.
func TestSetup_ServesTheControlPlane(t *testing.T) {
	key := testcerts.RSA(t, 2048)
	for k, v := range map[string]string{
		"AWS_REGION":                  "us-east-1",
		"AWS_CONFIG_FILE":             "/dev/null",
		"AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
		"AWS_EC2_METADATA_DISABLED":   "true",

		"APP_ENV_NAME":   "dev",
		"APP_PUBLIC_URL": "https://sealer.dev.example.com",
		"APP_REGISTRY": `agents:
  - id: dev-use1-blue
    cluster: dev-use1-blue
    region: use1
    capabilities: [seal]
    identity:
      aws:
        roleArn: arn:aws:iam::123456789012:role/sealer-agent-dev-use1-blue
`,
		"APP_AGENT_SESSION_KEY":          strings.Repeat("a", 32),
		"APP_USER_SESSION_KEY":           strings.Repeat("u", 32),
		"APP_DYNAMODB_TABLE":             "sealer-dev",
		"APP_GITHUB_ORG":                 "example-org",
		"APP_GITHUB_OAUTH_CLIENT_ID":     "client-id",
		"APP_GITHUB_OAUTH_CLIENT_SECRET": "client-secret",
		"APP_GITHUB_APP_ID":              "1",
		"APP_GITHUB_APP_PRIVATE_KEY":     string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
		"APP_KMS_TRANSIT_KEY_ID":         "alias/sealer-transit",
		"APP_LOG_LEVEL":                  "error",
	} {
		t.Setenv(k, v)
	}
	h, err := setup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	resp, err := h.invoke(ctx, event(http.MethodGet, "/healthz"))
	if err != nil || resp.StatusCode != http.StatusOK || !strings.Contains(string(body(t, resp)), `"status":"ok"`) {
		t.Fatalf("/healthz = %+v, %v", resp, err)
	}
	if resp.Headers["Strict-Transport-Security"] == "" {
		t.Errorf("no HSTS over https: %v", resp.Headers)
	}
	if resp, _ := h.invoke(ctx, event(http.MethodGet, "/api/v1/fleet")); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/api/v1/fleet = %d", resp.StatusCode)
	}

	login := event(http.MethodGet, "/api/v1/auth/login")
	login.RawQueryString = "return_to=%2Ffleet"
	resp, _ = h.invoke(ctx, login)
	location, _ := url.Parse(resp.Headers["Location"])
	if resp.StatusCode != http.StatusFound || location.Host != "github.com" || location.Query().Get("client_id") != "client-id" {
		t.Fatalf("login = %+v", resp)
	}
	if len(resp.Cookies) != 1 || !strings.HasPrefix(resp.Cookies[0], "sealer_oauth_state=") || !strings.Contains(resp.Cookies[0], "Secure") {
		t.Fatalf("login cookies = %q", resp.Cookies)
	}
}

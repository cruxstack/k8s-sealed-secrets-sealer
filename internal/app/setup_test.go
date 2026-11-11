package app

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/config"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/githubsetup"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/mockgithub"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/mockssm"
)

const appParameter = "arn:aws:ssm:us-east-1:000000000000:parameter/sealer/github-app"

// setupStack is a control plane whose GitHub App's credentials are in a
// parameter of the SSM mock, with the GitHub mock beside it.
type setupStack struct {
	cp     *httptest.Server
	github *httptest.Server
	ssm    *httptest.Server
	client *http.Client
}

func newSetupStack(t *testing.T) *setupStack {
	t.Helper()
	repos, err := mockgithub.Fixtures()
	if err != nil {
		t.Fatal(err)
	}
	st := &setupStack{ssm: httptest.NewServer(mockssm.New(nil).Handler())}
	t.Cleanup(st.ssm.Close)
	st.github = httptest.NewUnstartedServer(nil)
	ghURL := "http://" + st.github.Listener.Addr().String()
	st.github.Config.Handler = mockgithub.New(mockgithub.Options{
		Org: "example-org", Users: mockgithub.DefaultUsers(), Repos: repos, WebURL: ghURL,
	}).Handler()
	st.github.Start()
	t.Cleanup(st.github.Close)

	// the control plane's URL is in its configuration, so listen first
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	st.cp = &httptest.Server{Listener: ln, Config: &http.Server{}}
	cpURL := "http://" + ln.Addr().String()

	for k, v := range map[string]string{
		"APP_ENV_NAME":              "dev",
		"APP_PUBLIC_URL":            cpURL,
		"APP_REGISTRY":              "agents:\n" + agentLine("green", role("green")),
		"APP_AGENT_SESSION_KEY":     strings.Repeat("a", 32),
		"APP_USER_SESSION_KEY":      strings.Repeat("u", 32),
		"APP_DYNAMODB_TABLE":        "sealer",
		"APP_KMS_TRANSIT_KEY_ID":    "alias/sealer-transit",
		"APP_KMS_REGION":            "us-east-1",
		"APP_GITHUB_ORG":            "example-org",
		"APP_GITHUB_URL":            ghURL,
		"APP_GITHUB_API_URL":        ghURL,
		"APP_ALLOW_INSECURE_GITHUB": "true",
		"APP_GITHUB_APP_PARAMETER":  appParameter,
		"APP_SSM_ENDPOINT":          st.ssm.URL,
		// the SDK signs requests to the mock with something
		"AWS_ACCESS_KEY_ID":     "local",
		"AWS_SECRET_ACCESS_KEY": "local",
		"AWS_REGION":            "us-east-1",
	} {
		t.Setenv(k, v)
	}

	jar, _ := cookiejar.New(nil)
	st.client = &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return st
}

// start builds a control plane instance and serves it at the stack's URL.
func (st *setupStack) start(t *testing.T) *ControlPlane {
	t.Helper()
	cp := st.instance(t)
	st.cp.Config.Handler = cp
	st.cp.Start()
	t.Cleanup(st.cp.Close)
	return cp
}

// instance builds a control plane from the environment, as cmd/server does.
func (st *setupStack) instance(t *testing.T) *ControlPlane {
	t.Helper()
	ctx := context.Background()
	cfgs, err := config.LoadControlPlanes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := NewControlPlane(ctx, cfgs, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return cp
}

// reply is a response, read and closed.
type reply struct {
	method, url string
	StatusCode  int
	Header      http.Header
	Body        []byte
}

func (st *setupStack) do(t *testing.T, method, target string, form url.Values, headers map[string]string) reply {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	if strings.HasPrefix(target, "/") {
		target = st.cp.URL + target
	}
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := st.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return reply{method: method, url: target, StatusCode: resp.StatusCode, Header: resp.Header, Body: got}
}

func location(t *testing.T, resp reply, wantPrefix string) string {
	t.Helper()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, wantPrefix) {
		t.Fatalf("%s %s = %d to %q, want a redirect to %s...\n%s", resp.method, resp.url, resp.StatusCode, loc, wantPrefix, resp.Body)
	}
	return loc
}

// A control plane with no GitHub App yet serves only its setup page; an
// org owner creates the App there, and from then on people sign in with it
// and it reads repositories, in this instance and in any started since.
func TestSetUpTheGitHubApp(t *testing.T) {
	st := newSetupStack(t)
	cp := st.start(t)
	// another instance, started before the App exists, learns of it
	other := st.instance(t)
	xhr := map[string]string{"X-Requested-With": "XMLHttpRequest"}

	// --- before: every page is the setup page, and nobody signs in
	location(t, st.do(t, http.MethodGet, "/fleet", nil, nil), "/setup")
	if resp := st.do(t, http.MethodGet, "/api/v1/auth/login", nil, nil); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("sign-in before setup = %d", resp.StatusCode)
	}
	if csp := st.do(t, http.MethodGet, "/fleet", nil, nil).Header.Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' "+st.github.URL+";") {
		t.Fatalf("the setup page cannot post to GitHub: %s", csp)
	}
	resp := st.do(t, http.MethodGet, "/api/v1/setup", nil, nil)
	var status struct{ Org string }
	if resp.StatusCode != http.StatusOK || json.Unmarshal(resp.Body, &status) != nil || status.Org != "example-org" {
		t.Fatalf("setup status = %d", resp.StatusCode)
	}

	// --- the page starts the setup, and the person creates the App on GitHub
	resp = st.do(t, http.MethodPost, "/api/v1/setup/github-app", nil, xhr)
	var form struct{ Action, Manifest string }
	if resp.StatusCode != http.StatusOK || json.Unmarshal(resp.Body, &form) != nil {
		t.Fatalf("start = %d", resp.StatusCode)
	}
	action, _ := url.Parse(form.Action)
	resp = st.do(t, http.MethodPost, form.Action, url.Values{"manifest": {form.Manifest}}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("posting the manifest to GitHub = %d", resp.StatusCode)
	}
	callback := location(t, st.do(t, http.MethodPost, st.github.URL+"/_mock/organizations/example-org/apps",
		url.Values{"manifest": {form.Manifest}, "state": {action.Query().Get("state")}, "name": {"Sealer for example-org"}}, nil),
		st.cp.URL+githubsetup.CallbackPath+"?")

	// --- back at the control plane: the App is stored and in use, and the
	// person is sent on to install it
	install := location(t, st.do(t, http.MethodGet, callback, nil, nil), st.github.URL+"/apps/sealer-for-example-org/installations/new")
	stored, err := mustSSMStore(t, st).Load(context.Background())
	if err != nil || stored.Slug != "sealer-for-example-org" || stored.AppID == "" {
		t.Fatalf("stored = %+v, %v", stored, err)
	}
	location(t, st.do(t, http.MethodGet, install, nil, nil), st.cp.URL+"/?installation_id=")
	if resp := st.do(t, http.MethodGet, "/api/v1/setup", nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("setup status once set up = %d", resp.StatusCode)
	}
	if resp := st.do(t, http.MethodGet, "/fleet", nil, nil); resp.StatusCode == http.StatusFound {
		t.Fatal("pages still go to the setup page")
	}

	// --- people sign in with the new App, and it reads the repositories
	authorize := location(t, st.do(t, http.MethodGet, "/api/v1/auth/login", nil, nil), st.github.URL+"/login/oauth/authorize?")
	if u, _ := url.Parse(authorize); u.Query().Get("client_id") != stored.ClientID {
		t.Fatalf("sign-in is not with the new App's client: %s", authorize)
	}
	signedIn := location(t, st.do(t, http.MethodGet, authorize+"&login=alice", nil, nil), st.cp.URL+"/api/v1/auth/callback?")
	if loc := location(t, st.do(t, http.MethodGet, signedIn, nil, nil), "/"); strings.HasPrefix(loc, "/login") {
		t.Fatalf("sign-in with the new App failed: %s", loc)
	}
	resp = st.do(t, http.MethodGet, "/api/v1/repos", nil, xhr)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(resp.Body), "example-org/apps") {
		t.Fatalf("repositories through the new App = %d %s", resp.StatusCode, resp.Body)
	}

	// --- a second setup is refused, and the App kept
	st.do(t, http.MethodPost, form.Action, url.Values{"manifest": {form.Manifest}}, nil)
	callback = location(t, st.do(t, http.MethodPost, st.github.URL+"/_mock/organizations/example-org/apps",
		url.Values{"manifest": {form.Manifest}, "state": {action.Query().Get("state")}}, nil), st.cp.URL)
	if resp := st.do(t, http.MethodGet, callback, nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a callback once set up = %d", resp.StatusCode)
	}
	if again, _ := mustSSMStore(t, st).Load(context.Background()); again != stored {
		t.Fatal("the App set up first was replaced")
	}

	// --- the instance started before reads the parameter on a request
	other.nextCheck.Store(0)
	rec := httptest.NewRecorder()
	other.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/login", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("the other instance did not take up the App: %d", rec.Code)
	}
	// and one started now uses it from the start
	if !st.instance(t).configured.Load() || !cp.configured.Load() {
		t.Fatal("an instance started after setup is in setup mode")
	}
}

func mustAWSConfig(t *testing.T) aws.Config {
	t.Helper()
	cfg, err := awsconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func mustSSMStore(t *testing.T, st *setupStack) *githubsetup.SSMStore {
	t.Helper()
	s, err := githubsetup.NewSSMStore(mustAWSConfig(t), appParameter, st.ssm.URL)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

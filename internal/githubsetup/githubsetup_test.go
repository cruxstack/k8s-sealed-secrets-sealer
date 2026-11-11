package githubsetup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

const testPEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIk\n-----END RSA PRIVATE KEY-----\n"

func validCreds() Credentials {
	return Credentials{AppID: "42", Slug: "sealer-for-example-org", ClientID: "Iv1.abc", ClientSecret: "s3cret", PrivateKey: testPEM}
}

func TestCredentials(t *testing.T) {
	if err := validCreds().Validate(); err != nil {
		t.Fatal(err)
	}
	err := Credentials{AppID: "x", Slug: "Bad Slug", PrivateKey: "nope"}.Validate()
	for _, want := range []string{"app_id", "slug", "client_id", "client_secret", "private_key"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %s: %v", want, err)
		}
	}

	enc, err := validCreds().encode()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := parseCredentials(enc); err != nil || got != validCreds() {
		t.Fatalf("round trip = %+v, %v", got, err)
	}
	// an unreadable value is refused without being quoted
	_, err = parseCredentials(`{"app_id": "42", "secret_thing": "do-not-echo"}`)
	if err == nil || strings.Contains(err.Error(), "do-not-echo") {
		t.Fatalf("unknown field: %v", err)
	}
}

func TestManifest(t *testing.T) {
	m := newManifest("example-org", "https://sealer.example.com/")
	if m.RedirectURL != "https://sealer.example.com"+CallbackPath ||
		len(m.CallbackURLs) != 1 || m.CallbackURLs[0] != "https://sealer.example.com/api/v1/auth/callback" ||
		m.SetupURL != "https://sealer.example.com/" || m.URL != "https://sealer.example.com" {
		t.Errorf("urls: %+v", m)
	}
	if m.Public || m.HookAttributes.Active || len(m.DefaultEvents) != 0 || m.RequestOAuthOnInstall {
		t.Errorf("the app must be private, with no webhook or events: %+v", m)
	}
	if m.DefaultPermissions["contents"] != "write" || m.DefaultPermissions["pull_requests"] != "write" ||
		m.DefaultPermissions["metadata"] != "read" || m.DefaultPermissions["members"] != "read" || len(m.DefaultPermissions) != 4 {
		t.Errorf("permissions: %v", m.DefaultPermissions)
	}
	if got := defaultAppName("a-very-long-organization-name-indeed"); len(got) > maxAppName || !strings.HasPrefix(got, "Sealer for a-very") {
		t.Errorf("long name = %q", got)
	}
}

func TestParameterName(t *testing.T) {
	for arn, want := range map[string]string{
		"arn:aws:ssm:us-east-1:123456789012:parameter/sealer/github-app": "/sealer/github-app",
		"arn:aws:ssm:us-east-1:123456789012:parameter/sealer-github-app": "sealer-github-app",
	} {
		if got, ok := parameterName(arn); !ok || got != want {
			t.Errorf("%s = %q, %v", arn, got, ok)
		}
	}
	if _, ok := parameterName("arn:aws:ssm:us-east-1:123456789012:document/x"); ok {
		t.Error("a document ARN named a parameter")
	}
}

// fakeSSM is SSM in one account: parameters by name, readable by the ARN
// of that account.
type fakeSSM struct {
	mu      sync.Mutex
	account string
	params  map[string]string
	put     ssm.PutParameterInput
}

func (f *fakeSSM) GetParameter(_ context.Context, in *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	name := *in.Name
	if !strings.Contains(name, ":"+f.account+":") {
		return nil, &ssmtypes.ParameterNotFound{}
	}
	name, _ = parameterName(name)
	v, ok := f.params[name]
	if !ok {
		return nil, &ssmtypes.ParameterNotFound{}
	}
	if !aws.ToBool(in.WithDecryption) {
		return nil, errors.New("a securestring read without decryption")
	}
	return &ssm.GetParameterOutput{Parameter: &ssmtypes.Parameter{Value: aws.String(v)}}, nil
}

func (f *fakeSSM) PutParameter(_ context.Context, in *ssm.PutParameterInput, _ ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.put = *in
	if _, ok := f.params[*in.Name]; ok && !aws.ToBool(in.Overwrite) {
		return nil, &ssmtypes.ParameterAlreadyExists{}
	}
	f.params[*in.Name] = *in.Value
	return &ssm.PutParameterOutput{}, nil
}

func TestSSMStore(t *testing.T) {
	ctx := context.Background()
	const arn = "arn:aws:ssm:us-east-1:123456789012:parameter/sealer/github-app"
	fake := &fakeSSM{account: "123456789012", params: map[string]string{}}
	s, err := newSSMStore(fake, arn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx); !errors.Is(err, ErrNotSetUp) {
		t.Fatalf("empty Load = %v", err)
	}
	if err := s.Create(ctx, validCreds()); err != nil {
		t.Fatal(err)
	}
	if fake.put.Type != ssmtypes.ParameterTypeSecureString || aws.ToBool(fake.put.Overwrite) || *fake.put.Name != "/sealer/github-app" {
		t.Errorf("put = %+v", fake.put)
	}
	if got, err := s.Load(ctx); err != nil || got != validCreds() {
		t.Fatalf("Load = %+v, %v", got, err)
	}
	// written once: a second App is refused and the first kept
	other := validCreds()
	other.AppID = "43"
	if err := s.Create(ctx, other); !errors.Is(err, ErrAlreadySetUp) {
		t.Fatalf("second Create = %v", err)
	}
	if got, _ := s.Load(ctx); got.AppID != "42" {
		t.Fatalf("the first app was replaced: %+v", got)
	}

	// an ARN in another account is written here but never read back
	elsewhere, _ := newSSMStore(&fakeSSM{account: "123456789012", params: map[string]string{}},
		"arn:aws:ssm:us-east-1:210987654321:parameter/sealer/github-app")
	if err := elsewhere.Create(ctx, validCreds()); err == nil || !strings.Contains(err.Error(), "names another") {
		t.Fatalf("Create in another account = %v", err)
	}

	// a value the setup page did not write is refused
	fake.params["/sealer/github-app"] = `{"app_id": "42"}`
	if _, err := s.Load(ctx); err == nil || errors.Is(err, ErrNotSetUp) {
		t.Fatalf("Load of a bad value = %v", err)
	}
}

// fakeGitHub answers manifest conversions with the App each code made.
type fakeGitHub struct {
	mu    sync.Mutex
	apps  map[string]map[string]any // code -> conversion
	calls int
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	code, ok := strings.CutPrefix(r.URL.Path, "/app-manifests/")
	code, _ = strings.CutSuffix(code, "/conversions")
	app, found := f.apps[code]
	if r.Method != http.MethodPost || !ok || !found {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
		return
	}
	delete(f.apps, code)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(app)
}

func conversionFor(id int64, slug, owner, ownerType string) map[string]any {
	return map[string]any{
		"id": id, "slug": slug, "owner": map[string]any{"login": owner, "type": ownerType},
		"client_id": "Iv1.abc", "client_secret": "s3cret", "pem": testPEM,
	}
}

type setupHarness struct {
	h       *Handler
	gh      *fakeGitHub
	store   *MemoryStore
	created []Credentials
	logs    *bytes.Buffer
}

func newSetupHarness(t *testing.T) *setupHarness {
	t.Helper()
	gh := &fakeGitHub{apps: map[string]map[string]any{}}
	api := httptest.NewServer(gh)
	t.Cleanup(api.Close)
	sh := &setupHarness{gh: gh, store: NewMemoryStore(nil), logs: &bytes.Buffer{}}
	sh.h = New(Options{
		Store:     sh.store,
		Org:       "example-org",
		PublicURL: "https://sealer.example.com",
		GitHubURL: "https://github.example.com/",
		APIURL:    api.URL,
		OnCreated: func(_ context.Context, c Credentials) error {
			sh.created = append(sh.created, c)
			return nil
		},
		Logger: slog.New(slog.NewJSONHandler(sh.logs, nil)),
	})
	return sh
}

func (sh *setupHarness) do(method, target string, cookies []*http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	sh.h.ServeHTTP(rec, req)
	return rec
}

// start begins a setup as the page does and returns its state cookie and
// the state GitHub would send back.
func (sh *setupHarness) start(t *testing.T) (*http.Cookie, string) {
	t.Helper()
	rec := sh.do(http.MethodPost, "/api/v1/setup/github-app", nil, map[string]string{"X-Requested-With": "XMLHttpRequest"})
	if rec.Code != http.StatusOK {
		t.Fatalf("start = %d %s", rec.Code, rec.Body)
	}
	var out struct{ Action, Manifest string }
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	action, err := url.Parse(out.Action)
	if err != nil || action.Host != "github.example.com" || action.Path != "/organizations/example-org/settings/apps/new" {
		t.Fatalf("action = %q", out.Action)
	}
	var m manifest
	if err := json.Unmarshal([]byte(out.Manifest), &m); err != nil || m.RedirectURL != "https://sealer.example.com"+CallbackPath {
		t.Fatalf("manifest = %s (%v)", out.Manifest, err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "__Host-sealer_setup_state" || !cookies[0].HttpOnly || !cookies[0].Secure ||
		cookies[0].Value != action.Query().Get("state") {
		t.Fatalf("state cookie = %+v", cookies)
	}
	return cookies[0], cookies[0].Value
}

func TestHandler_Status(t *testing.T) {
	sh := newSetupHarness(t)
	rec := sh.do(http.MethodGet, "/api/v1/setup", nil, nil)
	var out struct {
		Org, GitHubURL, AppName string
		Permissions             []permission
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusOK || out.Org != "example-org" || len(out.Permissions) != 4 {
		t.Fatalf("status = %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("status says too much: %s", rec.Body)
	}
	if got := sh.h.FormAction(); got != "https://github.example.com" {
		t.Errorf("FormAction = %q", got)
	}
	if rec := sh.do(http.MethodGet, "/api/v1/setup/other", nil, nil); rec.Code != http.StatusNotFound {
		t.Errorf("unknown path = %d", rec.Code)
	}
}

func TestHandler_CreatesAndStoresTheApp(t *testing.T) {
	sh := newSetupHarness(t)
	cookie, state := sh.start(t)
	sh.gh.apps["abc123def456"] = conversionFor(42, "sealer-for-example-org", "Example-Org", "Organization")

	rec := sh.do(http.MethodGet, CallbackPath+"?code=abc123def456&state="+state, []*http.Cookie{cookie}, nil)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://github.example.com/apps/sealer-for-example-org/installations/new" {
		t.Fatalf("callback = %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if got, err := sh.store.Load(context.Background()); err != nil || got != validCreds() {
		t.Fatalf("stored = %+v, %v", got, err)
	}
	if len(sh.created) != 1 || sh.created[0].AppID != "42" {
		t.Fatalf("OnCreated = %+v", sh.created)
	}
	// the state is used once
	if c := rec.Result().Cookies(); len(c) != 1 || c[0].MaxAge >= 0 {
		t.Errorf("the state cookie is not cleared: %+v", c)
	}
	logs := sh.logs.String()
	if !strings.Contains(logs, `"event":"github_app.created"`) || strings.Contains(logs, "s3cret") || strings.Contains(logs, "PRIVATE KEY") {
		t.Errorf("logs: %s", logs)
	}
}

func TestHandler_Refuses(t *testing.T) {
	t.Run("start from another site", func(t *testing.T) {
		sh := newSetupHarness(t)
		if rec := sh.do(http.MethodPost, "/api/v1/setup/github-app", nil, nil); rec.Code != http.StatusForbidden {
			t.Fatalf("start without X-Requested-With = %d", rec.Code)
		}
	})

	for name, tc := range map[string]struct {
		cookie   bool
		state    string
		code     string
		owner    string
		kind     string
		want     string
		exchange bool
	}{
		"no state cookie":    {cookie: false, code: "abc123def456", owner: "example-org", kind: "Organization", want: ErrCodeState},
		"another state":      {cookie: true, state: "other", code: "abc123def456", owner: "example-org", kind: "Organization", want: ErrCodeState},
		"a code with a path": {cookie: true, code: "abc/../../x", owner: "example-org", kind: "Organization", want: ErrCodeGitHub},
		"an unknown code":    {cookie: true, code: "unknowncode1", owner: "example-org", kind: "Organization", want: ErrCodeGitHub, exchange: true},
		"another org's app":  {cookie: true, code: "abc123def456", owner: "attacker-org", kind: "Organization", want: ErrCodeWrongOwner, exchange: true},
		"a user's own app":   {cookie: true, code: "abc123def456", owner: "example-org", kind: "User", want: ErrCodeWrongOwner, exchange: true},
	} {
		t.Run(name, func(t *testing.T) {
			sh := newSetupHarness(t)
			cookie, state := sh.start(t)
			if tc.state != "" {
				state = tc.state
			}
			var cookies []*http.Cookie
			if tc.cookie {
				cookies = []*http.Cookie{cookie}
			}
			sh.gh.apps["abc123def456"] = conversionFor(42, "sealer-for-example-org", tc.owner, tc.kind)
			rec := sh.do(http.MethodGet, CallbackPath+"?code="+url.QueryEscape(tc.code)+"&state="+state, cookies, nil)
			if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/setup?error="+tc.want {
				t.Fatalf("callback = %d %s, want error %s", rec.Code, rec.Header().Get("Location"), tc.want)
			}
			if _, err := sh.store.Load(context.Background()); !errors.Is(err, ErrNotSetUp) || len(sh.created) != 0 {
				t.Fatalf("an app was stored: %v %+v", err, sh.created)
			}
			if exchanged := sh.gh.calls > 0; exchanged != tc.exchange {
				t.Errorf("exchanged = %v, want %v", exchanged, tc.exchange)
			}
		})
	}

	t.Run("already set up", func(t *testing.T) {
		sh := newSetupHarness(t)
		existing := validCreds()
		existing.AppID = "7"
		sh.store = NewMemoryStore(&existing)
		sh.h.opts.Store = sh.store
		cookie, state := sh.start(t)
		sh.gh.apps["abc123def456"] = conversionFor(42, "sealer-for-example-org", "example-org", "Organization")
		rec := sh.do(http.MethodGet, CallbackPath+"?code=abc123def456&state="+state, []*http.Cookie{cookie}, nil)
		if rec.Header().Get("Location") != "/setup?error="+ErrCodeAlreadySetUp {
			t.Fatalf("callback = %s", rec.Header().Get("Location"))
		}
		if got, _ := sh.store.Load(context.Background()); got.AppID != "7" || len(sh.created) != 0 {
			t.Fatalf("the app set up first was replaced: %+v", got)
		}
	})

	t.Run("the store fails", func(t *testing.T) {
		sh := newSetupHarness(t)
		sh.store.Fail(errors.New("access denied"))
		cookie, state := sh.start(t)
		sh.gh.apps["abc123def456"] = conversionFor(42, "sealer-for-example-org", "example-org", "Organization")
		rec := sh.do(http.MethodGet, CallbackPath+"?code=abc123def456&state="+state, []*http.Cookie{cookie}, nil)
		if rec.Header().Get("Location") != "/setup?error="+ErrCodeStore || len(sh.created) != 0 {
			t.Fatalf("callback = %s, created %+v", rec.Header().Get("Location"), sh.created)
		}
	})

	t.Run("too many codes a minute", func(t *testing.T) {
		sh := newSetupHarness(t)
		now := time.Unix(1_700_000_000, 0)
		sh.h.opts.Now = func() time.Time { return now }
		var last string
		for range maxExchanges + 1 {
			cookie, state := sh.start(t)
			rec := sh.do(http.MethodGet, CallbackPath+"?code=unknowncode1&state="+state, []*http.Cookie{cookie}, nil)
			last = rec.Header().Get("Location")
		}
		if last != "/setup?error="+ErrCodeBusy || sh.gh.calls != maxExchanges {
			t.Fatalf("after %d codes: %s, %d calls", maxExchanges+1, last, sh.gh.calls)
		}
		now = now.Add(time.Minute)
		cookie, state := sh.start(t)
		sh.gh.apps["abc123def456"] = conversionFor(42, "sealer-for-example-org", "example-org", "Organization")
		if rec := sh.do(http.MethodGet, CallbackPath+"?code=abc123def456&state="+state, []*http.Cookie{cookie}, nil); rec.Code != http.StatusFound || len(sh.created) != 1 {
			t.Fatalf("a minute later = %s", rec.Header().Get("Location"))
		}
	})
}

func TestHandler_HTTPCookies(t *testing.T) {
	h := New(Options{Store: NewMemoryStore(nil), Org: "example-org", PublicURL: "http://localhost:4100", GitHubURL: "http://localhost:4104"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup/github-app", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	h.ServeHTTP(rec, req)
	c := rec.Result().Cookies()
	if len(c) != 1 || c[0].Name != "sealer_setup_state" || c[0].Secure {
		t.Fatalf("cookie over http = %+v", c)
	}
}

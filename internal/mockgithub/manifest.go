package mockgithub

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// appManifest is the part of a GitHub App manifest the mock reads.
type appManifest struct {
	Name               string            `json:"name"`
	URL                string            `json:"url"`
	RedirectURL        string            `json:"redirect_url"`
	CallbackURLs       []string          `json:"callback_urls"`
	SetupURL           string            `json:"setup_url"`
	DefaultPermissions map[string]string `json:"default_permissions"`
}

// conversion is an App created from a manifest whose code has not been
// exchanged: GitHub hands its private key over once, in the exchange.
type conversion struct {
	app *registeredApp
	pem string
}

func parseManifest(raw string) (appManifest, bool) {
	var m appManifest
	if json.Unmarshal([]byte(raw), &m) != nil || m.URL == "" || m.RedirectURL == "" {
		return appManifest{}, false
	}
	if _, err := url.Parse(m.RedirectURL); err != nil {
		return appManifest{}, false
	}
	return m, true
}

var confirmPage = template.Must(template.New("confirm").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Mock GitHub: create a GitHub App</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 36rem; margin: 4rem auto">
<h1>Mock GitHub</h1>
<p>Create a GitHub App owned by <strong>{{.Org}}</strong>, with:</p>
<ul>{{range $name, $level := .Permissions}}<li>{{$name}}: {{$level}}</li>{{end}}</ul>
<form method="post" action="/_mock/organizations/{{.Org}}/apps">
<input type="hidden" name="manifest" value="{{.Manifest}}">
<input type="hidden" name="state" value="{{.State}}">
<p><label>GitHub App name <input name="name" value="{{.Name}}" maxlength="34"></label></p>
<button type="submit">Create GitHub App for {{.Org}}</button>
</form>
</body></html>`))

// newAppFromManifest is GitHub's page for a manifest posted to an org: it
// shows what the App will be, and creates it when confirmed. Anyone may
// post here; the mock does not check who owns the org.
func (s *Server) newAppFromManifest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	m, ok := parseManifest(r.PostForm.Get("manifest"))
	if !ok {
		http.Error(w, "invalid manifest", http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = confirmPage.Execute(w, map[string]any{
		"Org":         r.PathValue("org"),
		"Name":        m.Name,
		"Permissions": m.DefaultPermissions,
		"Manifest":    r.PostForm.Get("manifest"),
		"State":       r.URL.Query().Get("state"),
	})
}

// createApp creates the App the confirmed manifest describes, owned by the
// org it was posted to, and sends the browser to the manifest's redirect
// URL with a code for its credentials and the state it came with.
func (s *Server) createApp(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	m, ok := parseManifest(r.PostForm.Get("manifest"))
	if !ok {
		http.Error(w, "invalid manifest", http.StatusUnprocessableEntity)
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	if name == "" {
		name = m.Name
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		http.Error(w, "failed to make a key", http.StatusInternalServerError)
		return
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))

	code := random()
	s.mu.Lock()
	next := 1
	for _, a := range s.apps {
		if n, err := strconv.Atoi(a.id); err == nil && n >= next {
			next = n + 1
		}
	}
	app := &registeredApp{
		id:           strconv.Itoa(next),
		name:         name,
		slug:         s.uniqueSlugLocked(name),
		owner:        r.PathValue("org"),
		publicKey:    &key.PublicKey,
		clientID:     "Iv1.mock" + random()[:12],
		clientSecret: random(),
		callbackURLs: m.CallbackURLs,
		setupURL:     m.SetupURL,
		permissions:  m.DefaultPermissions,
	}
	s.apps = append(s.apps, app)
	s.conversions[code] = conversion{app: app, pem: pemKey}
	s.mu.Unlock()

	back, _ := url.Parse(m.RedirectURL)
	q := back.Query()
	q.Set("code", code)
	if state := r.PostForm.Get("state"); state != "" {
		q.Set("state", state)
	}
	back.RawQuery = q.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound)
}

// uniqueSlugLocked makes a slug from an App's name that no App has; s.mu
// must be held.
func (s *Server) uniqueSlugLocked(name string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(name) {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteRune(c)
		case b.Len() > 0 && !strings.HasSuffix(b.String(), "-"):
			b.WriteByte('-')
		}
	}
	base := strings.Trim(b.String(), "-")
	if base == "" {
		base = "app"
	}
	slug := base
	for n := 2; ; n++ {
		taken := false
		for _, a := range s.apps {
			taken = taken || a.slug == slug
		}
		if !taken {
			return slug
		}
		slug = base + "-" + strconv.Itoa(n)
	}
}

// convertManifest exchanges a manifest code, once, for the App's
// credentials. Like GitHub, it takes no credentials.
func (s *Server) convertManifest(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	c, ok := s.conversions[r.PathValue("code")]
	delete(s.conversions, r.PathValue("code"))
	s.mu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, "Not Found")
		return
	}
	a := c.app
	id, _ := strconv.ParseInt(a.id, 10, 64)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":             id,
		"slug":           a.slug,
		"name":           a.name,
		"owner":          map[string]any{"login": a.owner, "id": 9000, "type": "Organization"},
		"client_id":      a.clientID,
		"client_secret":  a.clientSecret,
		"webhook_secret": nil,
		"pem":            c.pem,
		"html_url":       s.webURL(r) + "/apps/" + a.slug,
		"permissions":    a.permissions,
	})
}

var installedPage = template.Must(template.New("installed").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Mock GitHub: installed</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 36rem; margin: 4rem auto">
<h1>Mock GitHub</h1>
<p>{{.}} is installed on every repository of its org.</p>
</body></html>`))

// installApp installs an App on every repository of the org that owns it,
// as someone choosing "All repositories" on GitHub would, then sends them
// to the App's setup URL.
func (s *Server) installApp(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	var app *registeredApp
	for i, a := range s.apps {
		if a.slug == r.PathValue("slug") {
			app = a
			if a.installationID == 0 {
				a.installationID = int64(200 + i)
			}
		}
	}
	var id int64
	if app != nil {
		id = app.installationID
	}
	s.mu.Unlock()
	if app == nil {
		http.NotFound(w, r)
		return
	}
	if app.setupURL != "" {
		next, err := url.Parse(app.setupURL)
		if err == nil {
			q := next.Query()
			q.Set("installation_id", strconv.FormatInt(id, 10))
			q.Set("setup_action", "install")
			next.RawQuery = q.Encode()
			http.Redirect(w, r, next.String(), http.StatusFound)
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = installedPage.Execute(w, app.slug)
}

package githubsetup

import "strings"

// Paths the App is registered with.
const (
	// CallbackPath is where GitHub sends the browser back, with a code,
	// once the App is created.
	CallbackPath = "/api/v1/setup/github-app/callback"
	// signInCallbackPath is the App's OAuth callback, for signing in.
	signInCallbackPath = "/api/v1/auth/callback"
)

// Permissions are what the App is created with: repository Contents and
// Pull requests (read and write) and Metadata (read) to read SealedSecret
// files and open pull requests, and organization Members (read) to check
// teams at sign-in. Installation tokens are minted with less (section 12).
var Permissions = map[string]string{
	"contents":      "write",
	"metadata":      "read",
	"pull_requests": "write",
	"members":       "read",
}

// maxAppName is the longest name GitHub takes for an App.
const maxAppName = 34

// manifest is a GitHub App manifest.
type manifest struct {
	Name                  string            `json:"name"`
	URL                   string            `json:"url"`
	Description           string            `json:"description"`
	HookAttributes        hookAttributes    `json:"hook_attributes"`
	RedirectURL           string            `json:"redirect_url"`
	CallbackURLs          []string          `json:"callback_urls"`
	SetupURL              string            `json:"setup_url"`
	Public                bool              `json:"public"`
	DefaultPermissions    map[string]string `json:"default_permissions"`
	DefaultEvents         []string          `json:"default_events"`
	RequestOAuthOnInstall bool              `json:"request_oauth_on_install"`
}

type hookAttributes struct {
	URL    string `json:"url"`
	Active bool   `json:"active"`
}

// newManifest describes the App for a control plane at publicURL: private
// to the org, no webhook, signing people in at the control plane, and
// sending whoever installs it back to the control plane.
func newManifest(org, publicURL string) manifest {
	base := strings.TrimSuffix(publicURL, "/")
	return manifest{
		Name:        defaultAppName(org),
		URL:         base,
		Description: "Seals Kubernetes secrets with Sealed Secrets: reads SealedSecret files, opens pull requests with sealed values, and signs people in.",
		// the control plane takes no webhooks; GitHub wants a URL all the
		// same when the attributes are given
		HookAttributes:     hookAttributes{URL: base + "/", Active: false},
		RedirectURL:        base + CallbackPath,
		CallbackURLs:       []string{base + signInCallbackPath},
		SetupURL:           base + "/",
		Public:             false,
		DefaultPermissions: Permissions,
		DefaultEvents:      []string{},
	}
}

// defaultAppName is the name the App is offered under; whoever creates it
// may change it on GitHub, where App names are unique.
func defaultAppName(org string) string {
	name := "Sealer for " + org
	if len(name) > maxAppName {
		name = strings.TrimRight(name[:maxAppName], "-")
	}
	return name
}

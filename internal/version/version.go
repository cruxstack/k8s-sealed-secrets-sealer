// Package version holds the build version, set at link time with
// -ldflags "-X github.com/cruxstack/k8s-sealed-secrets-sealer/internal/version.Version=v1.2.3".
package version

// Version is the release this binary was built from.
var Version = "dev"

// Package manifest finds the SealedSecret documents in a YAML file that
// belong to an env.
//
// A document belongs to the env when its env annotation equals the env's
// name; its region annotation says which region it is for, so a value that
// differs by region goes only into its regions' documents. The
// decryption label (name, namespace and scope) always comes from the
// document's own metadata, the same place the controller reads it, so it
// can never be chosen by a user.
//
// Optional hint annotations, under the env annotation's prefix, only help
// people: what the secret is for (<prefix>/description), the keys it should
// hold (<prefix>/keys) and where its docs are (<prefix>/docs). They never
// change what is sealed or where.
package manifest

import (
	"bytes"
	"errors"
	"io"
	"net/url"
	"sort"
	"strings"
	"unicode"

	ssv1alpha1 "github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	"go.yaml.in/yaml/v3"
	"k8s.io/apimachinery/pkg/util/validation"
)

// Scopes, as the controller derives them from a SealedSecret's annotations.
const (
	ScopeStrict        = "strict"
	ScopeNamespaceWide = "namespace-wide"
	ScopeClusterWide   = "cluster-wide"
)

// Limits on what is parsed.
const (
	MaxFileBytes     = 1 << 20
	MaxDocuments     = 100
	MaxKeysPerSecret = 200
	// limits on hint annotations; longer values are cut or ignored
	maxDescriptionRunes = 300
	maxDocsURLBytes     = 2048
)

// DefaultPrefix is the annotation prefix hints use when the env annotation
// has none.
const DefaultPrefix = "k8s-sealed-secrets-sealer"

// Default annotation keys (docs/design.md, "Annotations").
const (
	DefaultEnvAnnotation    = "k8s-sealed-secrets-sealer/env"
	DefaultRegionAnnotation = "k8s-sealed-secrets-sealer/region"
)

// Errors for files that cannot be read at all. Their messages are shown to
// users and never echo file content.
var (
	ErrTooLarge    = errors.New("file is too large")
	ErrInvalidYAML = errors.New("file is not valid YAML")
	ErrTooMany     = errors.New("file has too many documents")
	// ErrDuplicateKey refuses files that tools could read differently: a
	// duplicate metadata.namespace, say, might be taken first here and last
	// elsewhere.
	ErrDuplicateKey = errors.New("file has a duplicate key in a mapping")
)

// Annotations are the annotation keys that place a document in an env.
type Annotations struct {
	Env    string
	Region string
}

// Hint returns the key of a hint annotation: name under the env
// annotation's prefix.
func (a Annotations) Hint(name string) string {
	prefix, _, ok := strings.Cut(a.Env, "/")
	if !ok || prefix == "" {
		prefix = DefaultPrefix
	}
	return prefix + "/" + name
}

// Document is a SealedSecret in the env.
type Document struct {
	// Index is the document's position in the file, counting from 0.
	// Empty documents are not counted.
	Index     int    `json:"index"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Region    string `json:"region,omitempty"`
	Scope     string `json:"scope"`
	// Keys are the names in spec.encryptedData.
	Keys []string `json:"keys"`
	// Problem says why values cannot be sealed into this document; empty
	// when they can.
	Problem string `json:"problem,omitempty"`

	// Hints from optional annotations, for people: what the secret is for,
	// the keys it should hold, and an http(s) link to its docs.
	Description  string   `json:"description,omitempty"`
	ExpectedKeys []string `json:"expected_keys,omitempty"`
	Docs         string   `json:"docs,omitempty"`
}

// Sealable reports whether values can be sealed into the document.
func (d Document) Sealable() bool { return d.Problem == "" }

// IsRegion reports whether s can name a region: a lowercase DNS label (RFC
// 1123) of at most 63 characters, such as use1, like agents' regions in the
// registry. Regions are written into commit messages and pull requests, so
// nothing else is accepted.
func IsRegion(s string) bool { return s != "" && len(validation.IsDNS1123Label(s)) == 0 }

// Find returns the SealedSecret documents in content whose env annotation
// equals env. Other documents, and other envs' SealedSecrets, are ignored.
func Find(content []byte, ann Annotations, env string) ([]Document, error) {
	docs, err := parse(content)
	if err != nil {
		return nil, err
	}
	var out []Document
	for i, d := range docs {
		root := documentRoot(d)
		if root == nil || scalar(mapValue(root, "kind")) != "SealedSecret" {
			continue
		}
		meta := mapValue(root, "metadata")
		annotations := stringMap(mapValue(meta, "annotations"))
		if annotations[ann.Env] != env {
			continue
		}
		spec := mapValue(root, "spec")
		doc := Document{
			Index:     i,
			Name:      scalar(mapValue(meta, "name")),
			Namespace: scalar(mapValue(meta, "namespace")),
			Region:    annotations[ann.Region],
			Scope:     scope(annotations),
			Keys:      mapKeys(mapValue(spec, "encryptedData")),

			Description:  description(annotations[ann.Hint("description")]),
			ExpectedKeys: expectedKeys(annotations[ann.Hint("keys")]),
			Docs:         docsURL(annotations[ann.Hint("docs")]),
		}
		doc.Problem = problem(root, spec, doc)
		out = append(out, doc)
	}
	return out, nil
}

// problem returns why a document cannot be sealed into, or "".
func problem(root, spec *yaml.Node, d Document) string {
	switch {
	case scalar(mapValue(root, "apiVersion")) != "bitnami.com/v1alpha1":
		return "unsupported apiVersion; expected bitnami.com/v1alpha1"
	case d.Scope == ScopeClusterWide:
		return "cluster-wide scope is not allowed: anyone who can create a SealedSecret could decrypt it anywhere"
	case d.Name == "":
		return "metadata.name is missing"
	case len(validation.IsDNS1123Subdomain(d.Name)) > 0:
		return "metadata.name is not a valid name"
	case d.Namespace == "":
		return "metadata.namespace is missing; the decryption label needs it"
	case len(validation.IsDNS1123Label(d.Namespace)) > 0:
		return "metadata.namespace is not a valid namespace"
	case d.Region != "" && !IsRegion(d.Region):
		return "the region annotation is not a valid region: use a lowercase DNS label of at most 63 characters, such as use1"
	case spec != nil && mapValue(spec, "data") != nil:
		return "uses the legacy spec.data format"
	case !isMappingOrEmpty(mapValue(spec, "encryptedData")):
		return "spec.encryptedData is not a mapping"
	case len(d.Keys) > MaxKeysPerSecret:
		return "too many keys"
	}
	return ""
}

// scope mirrors the controller's SecretScope: the decryption label comes from
// the SealedSecret's own top-level annotations.
func scope(a map[string]string) string {
	switch {
	case a[ssv1alpha1.SealedSecretClusterWideAnnotation] == "true":
		return ScopeClusterWide
	case a[ssv1alpha1.SealedSecretNamespaceWideAnnotation] == "true":
		return ScopeNamespaceWide
	default:
		return ScopeStrict
	}
}

// parse decodes every document in content.
func parse(content []byte) ([]*yaml.Node, error) {
	if len(content) > MaxFileBytes {
		return nil, ErrTooLarge
	}
	dec := yaml.NewDecoder(bytes.NewReader(content))
	var docs []*yaml.Node
	for {
		var n yaml.Node
		err := dec.Decode(&n)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, ErrInvalidYAML
		}
		if hasDuplicateKey(&n) {
			return nil, ErrDuplicateKey
		}
		docs = append(docs, &n)
		if len(docs) > MaxDocuments {
			return nil, ErrTooMany
		}
	}
	return docs, nil
}

// hasDuplicateKey reports whether any mapping under n repeats a key. Aliases
// are not followed: the nodes they point at are checked where defined.
func hasDuplicateKey(n *yaml.Node) bool {
	if n == nil {
		return false
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind == yaml.ScalarNode {
				if seen[k.Value] {
					return true
				}
				seen[k.Value] = true
			}
		}
	}
	for _, c := range n.Content {
		if c.Kind != yaml.AliasNode && hasDuplicateKey(c) {
			return true
		}
	}
	return false
}

func documentRoot(d *yaml.Node) *yaml.Node {
	if d == nil || d.Kind != yaml.DocumentNode || len(d.Content) == 0 {
		return nil
	}
	root := resolve(d.Content[0])
	if root == nil || root.Kind != yaml.MappingNode {
		return nil
	}
	return root
}

// resolve follows aliases.
func resolve(n *yaml.Node) *yaml.Node {
	for i := 0; n != nil && n.Kind == yaml.AliasNode && i < 32; i++ {
		n = n.Alias
	}
	return n
}

// mapValue returns the value for key in a mapping node, or nil.
func mapValue(n *yaml.Node, key string) *yaml.Node {
	n = resolve(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return resolve(n.Content[i+1])
		}
	}
	return nil
}

func scalar(n *yaml.Node) string {
	n = resolve(n)
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

func stringMap(n *yaml.Node) map[string]string {
	out := map[string]string{}
	n = resolve(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return out
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if v := resolve(n.Content[i+1]); v != nil && v.Kind == yaml.ScalarNode {
			out[n.Content[i].Value] = v.Value
		}
	}
	return out
}

func mapKeys(n *yaml.Node) []string {
	keys := []string{}
	n = resolve(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return keys
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		keys = append(keys, n.Content[i].Value)
	}
	sort.Strings(keys)
	return keys
}

// isMappingOrEmpty accepts a mapping, an empty value ("encryptedData:") or
// no value at all.
func isMappingOrEmpty(n *yaml.Node) bool {
	return n == nil || n.Kind == yaml.MappingNode || (n.Kind == yaml.ScalarNode && n.Tag == "!!null")
}

// description returns a description hint on one line, without control or
// formatting characters (a bidi override could make it read as something
// else), cut to a readable length.
func description(v string) string {
	v = strings.Join(strings.Fields(v), " ")
	v = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, v)
	if r := []rune(v); len(r) > maxDescriptionRunes {
		v = strings.TrimSpace(string(r[:maxDescriptionRunes-1])) + "…"
	}
	return v
}

// expectedKeys returns the valid, distinct keys of a keys hint, separated
// by commas or spaces, in the order given.
func expectedKeys(v string) []string {
	var out []string
	seen := map[string]bool{}
	for _, k := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		if seen[k] || len(validation.IsConfigMapKey(k)) > 0 || len(out) == MaxKeysPerSecret {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	return out
}

// docsURL returns a docs hint when it is an absolute http(s) URL, the only
// links the UI shows.
func docsURL(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > maxDocsURLBytes {
		return ""
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return ""
	}
	return u.String()
}

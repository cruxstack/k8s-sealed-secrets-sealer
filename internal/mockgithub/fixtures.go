package mockgithub

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"sigs.k8s.io/yaml"
)

// fixtures holds the local stack's repositories: repos.yaml lists them, and
// <owner>/<name>/ holds each one's files.
//
//go:embed all:fixtures
var fixtures embed.FS

// Fixtures returns the local stack's repositories.
func Fixtures() ([]Repo, error) {
	raw, err := fixtures.ReadFile("fixtures/repos.yaml")
	if err != nil {
		return nil, err
	}
	var list struct {
		Repos []Repo `json:"repos"`
	}
	if err := yaml.UnmarshalStrict(raw, &list); err != nil {
		return nil, fmt.Errorf("failed to read fixtures/repos.yaml: %w", err)
	}
	for i := range list.Repos {
		r := &list.Repos[i]
		root := path.Join("fixtures", r.Owner, r.Name)
		r.Files = map[string]string{}
		err := fs.WalkDir(fixtures, root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, err := fixtures.ReadFile(p)
			if err != nil {
				return err
			}
			r.Files[strings.TrimPrefix(p, root+"/")] = string(b)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("failed to read the files of %s/%s: %w", r.Owner, r.Name, err)
		}
	}
	return list.Repos, nil
}

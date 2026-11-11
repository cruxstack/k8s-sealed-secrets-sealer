package mockgithub

import (
	"crypto/sha1" //nolint:gosec // Git object IDs, not security
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Repo is a mock repository. Its Files are the default branch's first
// commit.
type Repo struct {
	Owner         string            `json:"owner"`
	Name          string            `json:"name"`
	Private       bool              `json:"private"`
	DefaultBranch string            `json:"defaultBranch"`
	Permissions   map[string]string `json:"permissions"` // login -> admin, write or read
	Files         map[string]string `json:"-"`
}

// repoState is a repository's Git objects and refs. Trees are kept flat
// (path to blob), which is all the API the sealer uses needs.
type repoState struct {
	Repo
	blobs   map[string][]byte
	trees   map[string]map[string]string
	commits map[string]commit
	refs    map[string]string // "heads/main" -> commit
	pulls   []pullRecord
}

type commit struct {
	Tree    string
	Parents []string
	Message string
	Author  string
	Date    time.Time
}

func newRepoState(r Repo) *repoState {
	st := &repoState{
		Repo:    r,
		blobs:   map[string][]byte{},
		trees:   map[string]map[string]string{},
		commits: map[string]commit{},
		refs:    map[string]string{},
	}
	files := map[string]string{}
	for p, content := range r.Files {
		files[p] = st.putBlob([]byte(content))
	}
	tree := st.putTree(files)
	head := st.putCommit(commit{Tree: tree, Message: "Initial commit", Author: "mock", Date: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
	st.refs["heads/"+r.DefaultBranch] = head
	return st
}

// putBlob stores content under its Git blob ID.
func (st *repoState) putBlob(content []byte) string {
	h := sha1.New() //nolint:gosec // Git object IDs
	fmt.Fprintf(h, "blob %d\x00", len(content))
	h.Write(content)
	id := hex.EncodeToString(h.Sum(nil))
	st.blobs[id] = content
	return id
}

func (st *repoState) putTree(files map[string]string) string {
	b, _ := json.Marshal(files) // sorted keys: the same files give the same ID
	id := objectID("tree", b)
	st.trees[id] = files
	return id
}

func (st *repoState) putCommit(c commit) string {
	b, _ := json.Marshal(c)
	id := objectID("commit", b)
	st.commits[id] = c
	return id
}

func objectID(kind string, b []byte) string {
	h := sha1.New() //nolint:gosec // Git object IDs
	fmt.Fprintf(h, "%s %d\x00", kind, len(b))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

func (st *repoState) json() map[string]any {
	return map[string]any{
		"name":           st.Name,
		"full_name":      st.Owner + "/" + st.Name,
		"private":        st.Private,
		"archived":       false,
		"default_branch": st.DefaultBranch,
		"owner":          map[string]string{"login": st.Owner},
	}
}

// repo returns the repository in the request path, or writes a 404.
func (s *Server) repo(w http.ResponseWriter, r *http.Request) (*repoState, bool) {
	key := strings.ToLower(r.PathValue("owner") + "/" + r.PathValue("repo"))
	st, ok := s.repos[key]
	if !ok {
		writeError(w, http.StatusNotFound, "Not Found")
	}
	return st, ok
}

func (s *Server) installationRepositories(w http.ResponseWriter, r *http.Request) {
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if perPage <= 0 || perPage > 100 {
		perPage = 30
	}
	if page <= 0 {
		page = 1
	}
	s.mu.Lock()
	keys := make([]string, 0, len(s.repos))
	for k := range s.repos {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []map[string]any
	for i, k := range keys {
		if i >= (page-1)*perPage && i < page*perPage {
			out = append(out, s.repos[k].json())
		}
	}
	s.mu.Unlock()
	if out == nil {
		out = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"total_count": len(keys), "repositories": out})
}

func (s *Server) getRepo(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.repo(w, r); ok {
		writeJSON(w, http.StatusOK, st.json())
	}
}

// collaboratorPermission answers like GitHub: the legacy permission summary
// (maintain reads as write, triage as read) and the user.
func (s *Server) collaboratorPermission(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repo(w, r)
	if !ok {
		return
	}
	u, ok := s.user(r.PathValue("username"))
	if !ok {
		writeError(w, http.StatusNotFound, "Not Found")
		return
	}
	perm := st.Permissions[u.Login]
	switch perm {
	case "admin", "write", "read":
	case "maintain":
		perm = "write"
	case "triage":
		perm = "read"
	default:
		perm = "none"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"permission": perm,
		"role_name":  perm,
		"user":       map[string]any{"id": u.ID, "login": u.Login},
	})
}

// gitRef serves GET /repos/{owner}/{repo}/git/ref/{ref...}.
func (s *Server) gitRef(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repo(w, r)
	if !ok {
		return
	}
	ref := r.PathValue("ref")
	sha, ok := st.refs[ref]
	if !ok {
		writeError(w, http.StatusNotFound, "Not Found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ref":    "refs/" + ref,
		"object": map[string]string{"sha": sha, "type": "commit"},
	})
}

// gitTree serves a commit's tree; only recursive listing is supported.
func (s *Server) gitTree(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repo(w, r)
	if !ok {
		return
	}
	sha := r.PathValue("sha")
	treeID := sha
	if c, ok := st.commits[sha]; ok {
		treeID = c.Tree
	}
	files, ok := st.trees[treeID]
	if !ok || r.URL.Query().Get("recursive") == "" {
		writeError(w, http.StatusNotFound, "Not Found")
		return
	}
	var entries []map[string]any
	dirs := map[string]bool{}
	for p, blob := range files {
		for d := path.Dir(p); d != "."; d = path.Dir(d) {
			dirs[d] = true
		}
		entries = append(entries, map[string]any{"path": p, "mode": "100644", "type": "blob", "sha": blob, "size": len(st.blobs[blob])})
	}
	for d := range dirs {
		entries = append(entries, map[string]any{"path": d, "mode": "040000", "type": "tree", "sha": objectID("tree", []byte(treeID+d))})
	}
	slices.SortFunc(entries, func(a, b map[string]any) int { return strings.Compare(a["path"].(string), b["path"].(string)) })
	writeJSON(w, http.StatusOK, map[string]any{"sha": treeID, "tree": entries, "truncated": false})
}

func (s *Server) gitBlob(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repo(w, r)
	if !ok {
		return
	}
	content, ok := st.blobs[r.PathValue("sha")]
	if !ok {
		writeError(w, http.StatusNotFound, "Not Found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sha":      r.PathValue("sha"),
		"size":     len(content),
		"encoding": "base64",
		"content":  base64.StdEncoding.EncodeToString(content),
	})
}

// Push commits files on top of a branch as author, as a person pushing to
// a pull request's branch would, and returns the commit. A branch that does
// not exist starts from the default branch. False means the repository does
// not exist. For tests.
func (s *Server) Push(owner, repo, branch, author string, files map[string]string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repos[strings.ToLower(owner+"/"+repo)]
	if !ok {
		return "", false
	}
	head, ok := st.refs["heads/"+branch]
	if !ok {
		head = st.refs["heads/"+st.DefaultBranch]
	}
	tree := map[string]string{}
	for p, blob := range st.trees[st.commits[head].Tree] {
		tree[p] = blob
	}
	for p, content := range files {
		tree[p] = st.putBlob([]byte(content))
	}
	sha := st.putCommit(commit{Tree: st.putTree(tree), Parents: []string{head}, Message: "Push", Author: author, Date: time.Now().UTC()})
	st.refs["heads/"+branch] = sha
	for i, p := range st.pulls {
		if p.Head == branch && !p.Closed {
			st.pulls[i].HeadSHA = sha
		}
	}
	return sha, true
}

// File returns a file's content on a branch, for tests.
func (s *Server) File(owner, repo, branch, filePath string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repos[strings.ToLower(owner+"/"+repo)]
	if !ok {
		return "", false
	}
	head, ok := st.refs["heads/"+branch]
	if !ok {
		return "", false
	}
	blob, ok := st.trees[st.commits[head].Tree][filePath]
	if !ok {
		return "", false
	}
	return string(st.blobs[blob]), true
}

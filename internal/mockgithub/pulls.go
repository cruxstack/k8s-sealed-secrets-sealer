package mockgithub

import (
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// pullRecord is a pull request in a mock repository.
type pullRecord struct {
	Number  int
	Title   string
	Body    string
	Head    string // branch
	Base    string // branch
	HeadSHA string // follows the branch while the pull request is open
	BaseSHA string // the base branch's head when the pull request opened
	Created time.Time
	Closed  bool
}

func (p pullRecord) state() string {
	if p.Closed {
		return "closed"
	}
	return "open"
}

func (s *Server) pullJSONView(r *http.Request, st *repoState, p pullRecord) map[string]any {
	return map[string]any{
		"number":   p.Number,
		"state":    p.state(),
		"title":    p.Title,
		"body":     p.Body,
		"html_url": s.webURL(r) + "/" + st.Owner + "/" + st.Name + "/pull/" + strconv.Itoa(p.Number),
		"head":     map[string]string{"ref": p.Head, "sha": p.HeadSHA},
		"base":     map[string]string{"ref": p.Base, "sha": p.BaseSHA},
	}
}

func (s *Server) webURL(r *http.Request) string {
	if s.opts.WebURL != "" {
		return strings.TrimSuffix(s.opts.WebURL, "/")
	}
	return "http://" + r.Host
}

// decode reads a JSON request body, or answers 400.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "Problems parsing JSON")
		return false
	}
	return true
}

func (s *Server) createBlob(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if !decode(w, r, &in) {
		return
	}
	content := []byte(in.Content)
	if in.Encoding == "base64" {
		b, err := base64.StdEncoding.DecodeString(in.Content)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, "Invalid base64 content")
			return
		}
		content = b
	} else if in.Encoding != "" && in.Encoding != "utf-8" {
		writeError(w, http.StatusUnprocessableEntity, "Invalid encoding")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repo(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"sha": st.putBlob(content)})
}

func (s *Server) getCommit(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repo(w, r)
	if !ok {
		return
	}
	sha := r.PathValue("sha")
	c, ok := st.commits[sha]
	if !ok {
		writeError(w, http.StatusNotFound, "Not Found")
		return
	}
	writeJSON(w, http.StatusOK, commitJSON(sha, c))
}

// commitJSON is a commit as the Git database API describes it. Its author
// commits it too, as GitHub has an App's bot do for commits made through
// the API without either.
func commitJSON(sha string, c commit) map[string]any {
	parents := []map[string]string{}
	for _, p := range c.Parents {
		parents = append(parents, map[string]string{"sha": p})
	}
	person := map[string]string{"name": c.Author, "email": c.Author + "@users.noreply.github.com"}
	return map[string]any{
		"sha":       sha,
		"message":   c.Message,
		"tree":      map[string]string{"sha": c.Tree},
		"parents":   parents,
		"author":    person,
		"committer": person,
	}
}

// createTree builds a tree from base_tree and the given entries. Trees are
// flat, so paths are taken whole.
func (s *Server) createTree(w http.ResponseWriter, r *http.Request) {
	var in struct {
		BaseTree string `json:"base_tree"`
		Tree     []struct {
			Path    string  `json:"path"`
			Mode    string  `json:"mode"`
			Type    string  `json:"type"`
			SHA     *string `json:"sha"`
			Content *string `json:"content"`
		} `json:"tree"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repo(w, r)
	if !ok {
		return
	}
	files := map[string]string{}
	if in.BaseTree != "" {
		base, ok := st.trees[in.BaseTree]
		if !ok {
			writeError(w, http.StatusUnprocessableEntity, "Invalid base_tree")
			return
		}
		for p, b := range base {
			files[p] = b
		}
	}
	for _, e := range in.Tree {
		if e.Type != "blob" || (e.Mode != "100644" && e.Mode != "100755") || e.Path == "" || strings.HasPrefix(e.Path, "/") {
			writeError(w, http.StatusUnprocessableEntity, "Invalid tree entry")
			return
		}
		switch {
		case e.Content != nil:
			files[e.Path] = st.putBlob([]byte(*e.Content))
		case e.SHA == nil:
			delete(files, e.Path)
		default:
			if _, ok := st.blobs[*e.SHA]; !ok {
				writeError(w, http.StatusUnprocessableEntity, "Invalid tree entry: blob not found")
				return
			}
			files[e.Path] = *e.SHA
		}
	}
	writeJSON(w, http.StatusCreated, map[string]string{"sha": st.putTree(files)})
}

func (s *Server) createCommit(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Message string   `json:"message"`
		Tree    string   `json:"tree"`
		Parents []string `json:"parents"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repo(w, r)
	if !ok {
		return
	}
	if _, ok := st.trees[in.Tree]; !ok || in.Message == "" {
		writeError(w, http.StatusUnprocessableEntity, "Invalid tree or message")
		return
	}
	for _, p := range in.Parents {
		if _, ok := st.commits[p]; !ok {
			writeError(w, http.StatusUnprocessableEntity, "Invalid parent")
			return
		}
	}
	c := commit{Tree: in.Tree, Parents: in.Parents, Message: in.Message, Author: "sealer[bot]", Date: time.Now().UTC()}
	writeJSON(w, http.StatusCreated, commitJSON(st.putCommit(c), c))
}

func (s *Server) createRef(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Ref string `json:"ref"`
		SHA string `json:"sha"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repo(w, r)
	if !ok {
		return
	}
	ref, ok := strings.CutPrefix(in.Ref, "refs/")
	if !ok || !strings.HasPrefix(ref, "heads/") {
		writeError(w, http.StatusUnprocessableEntity, "Reference name is invalid")
		return
	}
	if _, exists := st.refs[ref]; exists {
		writeError(w, http.StatusUnprocessableEntity, "Reference already exists")
		return
	}
	if _, ok := st.commits[in.SHA]; !ok {
		writeError(w, http.StatusUnprocessableEntity, "Object does not exist")
		return
	}
	st.refs[ref] = in.SHA
	writeJSON(w, http.StatusCreated, map[string]any{"ref": in.Ref, "object": map[string]string{"sha": in.SHA, "type": "commit"}})
}

// updateRef moves a branch: forward, or anywhere with force.
func (s *Server) updateRef(w http.ResponseWriter, r *http.Request) {
	var in struct {
		SHA   string `json:"sha"`
		Force bool   `json:"force"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repo(w, r)
	if !ok {
		return
	}
	ref := r.PathValue("ref")
	old, exists := st.refs[ref]
	switch {
	case !exists:
		writeError(w, http.StatusUnprocessableEntity, "Reference does not exist")
		return
	case st.commits[in.SHA].Tree == "":
		writeError(w, http.StatusUnprocessableEntity, "Object does not exist")
		return
	case !in.Force && !st.descends(in.SHA, old):
		writeError(w, http.StatusUnprocessableEntity, "Update is not a fast forward")
		return
	}
	st.refs[ref] = in.SHA
	for i, p := range st.pulls {
		if !p.Closed && "heads/"+p.Head == ref {
			st.pulls[i].HeadSHA = in.SHA
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ref": "refs/" + ref, "object": map[string]string{"sha": in.SHA, "type": "commit"}})
}

// descends reports whether commit has ancestor among its first parents.
func (st *repoState) descends(commit, ancestor string) bool {
	for c := commit; c != ""; {
		if c == ancestor {
			return true
		}
		parents := st.commits[c].Parents
		if len(parents) == 0 {
			return false
		}
		c = parents[0]
	}
	return false
}

// deleteRef deletes a branch, closing the pull requests open from it, as
// GitHub does.
func (s *Server) deleteRef(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repo(w, r)
	if !ok {
		return
	}
	ref := r.PathValue("ref")
	if _, exists := st.refs[ref]; !exists || ref == "heads/"+st.DefaultBranch {
		writeError(w, http.StatusUnprocessableEntity, "Reference does not exist")
		return
	}
	delete(st.refs, ref)
	for i, p := range st.pulls {
		if "heads/"+p.Head == ref {
			st.pulls[i].Closed = true
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// listPulls lists pull requests, newest first, filtered like GitHub's by
// state (open by default) and head ("owner:branch").
func (s *Server) listPulls(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	if state == "" {
		state = "open"
	}
	headOwner, headBranch, byHead := strings.Cut(q.Get("head"), ":")
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repo(w, r)
	if !ok {
		return
	}
	out := []map[string]any{}
	for i := len(st.pulls) - 1; i >= 0; i-- {
		p := st.pulls[i]
		switch {
		case state != "all" && p.state() != state:
		case byHead && (!strings.EqualFold(headOwner, st.Owner) || p.Head != headBranch):
		default:
			out = append(out, s.pullJSONView(r, st, p))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// updatePull changes a pull request's title and description.
func (s *Server) updatePull(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Title *string `json:"title"`
		Body  *string `json:"body"`
	}
	if !decode(w, r, &in) {
		return
	}
	n, _ := strconv.Atoi(r.PathValue("number"))
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repo(w, r)
	if !ok {
		return
	}
	if n < 1 || n > len(st.pulls) {
		writeError(w, http.StatusNotFound, "Not Found")
		return
	}
	p := &st.pulls[n-1]
	if in.Title != nil {
		p.Title = *in.Title
	}
	if in.Body != nil {
		p.Body = *in.Body
	}
	writeJSON(w, http.StatusOK, s.pullJSONView(r, st, *p))
}

func (s *Server) createPull(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Title string `json:"title"`
		Body  string `json:"body"`
		Head  string `json:"head"`
		Base  string `json:"base"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repo(w, r)
	if !ok {
		return
	}
	headSHA, headOK := st.refs["heads/"+in.Head]
	baseSHA, baseOK := st.refs["heads/"+in.Base]
	switch {
	case strings.TrimSpace(in.Title) == "":
		writeError(w, http.StatusUnprocessableEntity, "Validation Failed: title is missing")
		return
	case !headOK || !baseOK || in.Head == in.Base:
		writeError(w, http.StatusUnprocessableEntity, "Validation Failed: head or base is invalid")
		return
	case slices.ContainsFunc(st.pulls, func(p pullRecord) bool { return p.Head == in.Head && !p.Closed }):
		writeError(w, http.StatusUnprocessableEntity, "Validation Failed: A pull request already exists for "+in.Head)
		return
	}
	p := pullRecord{
		Number:  len(st.pulls) + 1,
		Title:   in.Title,
		Body:    in.Body,
		Head:    in.Head,
		Base:    in.Base,
		HeadSHA: headSHA,
		BaseSHA: baseSHA,
		Created: time.Now().UTC(),
	}
	st.pulls = append(st.pulls, p)
	writeJSON(w, http.StatusCreated, s.pullJSONView(r, st, p))
}

// PullFile is a file a pull request changes.
type PullFile struct {
	Path   string `json:"path"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// Pull is a pull request with its commits and changed files, for the mock's
// page and tests. It is not a GitHub API shape.
type Pull struct {
	Number int `json:"number"`
	// State is "open" or "closed".
	State   string     `json:"state"`
	Title   string     `json:"title"`
	Body    string     `json:"body"`
	Head    string     `json:"head"`
	Base    string     `json:"base"`
	Commits []string   `json:"commits"`
	Message string     `json:"message"`
	Files   []PullFile `json:"files"`
}

// pullRequest returns a pull request in a repository, or false.
func (s *Server) pullRequest(owner, repo string, number int) (Pull, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repos[strings.ToLower(owner+"/"+repo)]
	if !ok || number < 1 || number > len(st.pulls) {
		return Pull{}, false
	}
	p := st.pulls[number-1]
	v := Pull{Number: p.Number, State: p.state(), Title: p.Title, Body: p.Body, Head: p.Head, Base: p.Base, Files: []PullFile{}}
	// the commits from the head back to the base
	for c := p.HeadSHA; c != "" && c != p.BaseSHA; {
		v.Commits = append(v.Commits, c)
		if v.Message == "" {
			v.Message = st.commits[c].Message
		}
		parents := st.commits[c].Parents
		if len(parents) == 0 {
			break
		}
		c = parents[0]
	}
	before := st.trees[st.commits[p.BaseSHA].Tree]
	after := st.trees[st.commits[p.HeadSHA].Tree]
	paths := map[string]bool{}
	for f := range before {
		paths[f] = true
	}
	for f := range after {
		paths[f] = true
	}
	for f := range paths {
		if before[f] != after[f] {
			v.Files = append(v.Files, PullFile{Path: f, Before: string(st.blobs[before[f]]), After: string(st.blobs[after[f]])})
		}
	}
	slices.SortFunc(v.Files, func(a, b PullFile) int { return strings.Compare(a.Path, b.Path) })
	return v, true
}

// PullRequest returns a pull request, for tests.
func (s *Server) PullRequest(owner, repo string, number int) (Pull, bool) {
	return s.pullRequest(owner, repo, number)
}

// pullJSON serves GET /_mock/repos/{owner}/{repo}/pulls/{number}, which the
// end-to-end tests read; it needs no token.
func (s *Server) pullJSON(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.PathValue("number"))
	v, ok := s.pullRequest(r.PathValue("owner"), r.PathValue("repo"), n)
	if !ok {
		writeError(w, http.StatusNotFound, "Not Found")
		return
	}
	writeJSON(w, http.StatusOK, v)
}

var pullPage = template.Must(template.New("pull").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>{{.Title}} · #{{.Number}}</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 72rem; margin: 2rem auto; padding: 0 1rem; color: #1f2328 }
.meta { color: #59636e } pre { white-space: pre-wrap; word-break: break-all }
.box { border: 1px solid #d1d9e0; border-radius: 6px; margin: 1rem 0 } .box h3 { margin: 0; padding: .5rem .75rem; background: #f6f8fa; font: 600 .875rem ui-monospace, monospace; border-bottom: 1px solid #d1d9e0 }
.diff { margin: 0; font: .75rem/1.5 ui-monospace, monospace; overflow-x: auto } .diff div { padding: 0 .75rem; white-space: pre }
.add { background: #dafbe1 } .del { background: #ffebe9 } .gap { color: #59636e; background: #f6f8fa }
</style></head>
<body>
<p class="meta">Mock GitHub</p>
<h1>{{.Title}} <span class="meta">#{{.Number}}</span></h1>
<p class="meta">Open: sealer[bot] wants to merge {{len .Commits}} commit into <code>{{.Base}}</code> from <code>{{.Head}}</code></p>
<div class="box"><h3>Description</h3><pre style="margin:0;padding:.75rem">{{.Body}}</pre></div>
<div class="box"><h3>Commit message</h3><pre style="margin:0;padding:.75rem">{{.Message}}</pre></div>
{{range .Diffs}}<div class="box"><h3>{{.Path}}</h3><div class="diff">{{range .Lines}}<div class="{{.Class}}">{{.Text}}</div>{{end}}</div></div>
{{end}}</body></html>`))

// pullHTML serves the pull request page its html_url points at.
func (s *Server) pullHTML(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.PathValue("number"))
	v, ok := s.pullRequest(r.PathValue("owner"), r.PathValue("repo"), n)
	if !ok {
		http.NotFound(w, r)
		return
	}
	type fileDiff struct {
		Path  string
		Lines []diffLine
	}
	var diffs []fileDiff
	for _, f := range v.Files {
		diffs = append(diffs, fileDiff{Path: f.Path, Lines: diff(f.Before, f.After)})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	_ = pullPage.Execute(w, map[string]any{
		"Number": v.Number, "Title": v.Title, "Body": v.Body, "Base": v.Base, "Head": v.Head,
		"Commits": v.Commits, "Message": v.Message, "Diffs": diffs,
	})
}

type diffLine struct {
	Class string
	Text  string
}

// diff is a line diff with three lines of context, enough for the mock's
// page.
func diff(before, after string) []diffLine {
	a, b := splitLines(before), splitLines(after)
	if len(a)*len(b) > 4_000_000 {
		return []diffLine{{Class: "gap", Text: "(too large to diff)"}}
	}
	// longest common subsequence, from the end
	lcs := make([][]int, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var all []diffLine
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case i < len(a) && j < len(b) && a[i] == b[j]:
			all = append(all, diffLine{Text: "  " + a[i]})
			i, j = i+1, j+1
		case i < len(a) && (j == len(b) || lcs[i+1][j] >= lcs[i][j+1]):
			all = append(all, diffLine{Class: "del", Text: "- " + a[i]})
			i++
		default:
			all = append(all, diffLine{Class: "add", Text: "+ " + b[j]})
			j++
		}
	}
	// keep three lines around each change
	const context = 3
	keep := make([]bool, len(all))
	for k, l := range all {
		if l.Class != "" {
			for c := max(0, k-context); c <= min(len(all)-1, k+context); c++ {
				keep[c] = true
			}
		}
	}
	var out []diffLine
	for k, l := range all {
		switch {
		case keep[k]:
			out = append(out, l)
		case k == 0 || keep[k-1]:
			out = append(out, diffLine{Class: "gap", Text: "  …"})
		}
	}
	return out
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

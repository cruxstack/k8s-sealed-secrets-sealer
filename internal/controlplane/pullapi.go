package controlplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/githubapp"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/repos"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/userauth"
)

// Pull request limits.
const (
	// pullRequestLock is how long a session stays locked while a pull
	// request is opened from it: longer than the request can take.
	pullRequestLock = 2 * time.Minute
	// pullRequestTimeout bounds opening a pull request, GitHub's writes
	// included, and pullRequestFinish ending or unlocking the session
	// afterwards: together well within the 30 seconds API Gateway, a
	// Lambda function and the HTTP server give a request.
	pullRequestTimeout = 20 * time.Second
	pullRequestFinish  = 3 * time.Second
	// maxChangesPerSession bounds a session's pending changes, and so what
	// one pull request carries.
	maxChangesPerSession = 50
	// maxTitleLength is the longest title that names the file and key;
	// longer ones only count them.
	maxTitleLength = 120
)

// pullRequestView is an opened pull request.
type pullRequestView struct {
	Number  int    `json:"number"`
	URL     string `json:"url"`
	Branch  string `json:"branch"`
	Title   string `json:"title"`
	Files   int    `json:"files"`
	Changes int    `json:"changes"`
}

// createPullRequest opens a pull request with a session's pending changes,
// on a new branch from the session's commit, and ends the session. The
// session is locked meanwhile, so nothing is sealed into it or removed from
// it while the pull request is being made. An attempt that failed part way,
// or whose answer was lost, can be repeated: the session's branch and the
// pull request open from it are reused (githubapp.CreatePullRequest), so a
// session opens one pull request at most.
func (s *Server) createPullRequest(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.currentSession(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), pullRequestTimeout)
	defer cancel()
	user := userauth.UserFrom(ctx)
	repoKey := store.RepoKey(sess.Owner, sess.Repo)
	now := s.now().UTC()

	locked, err := s.store.LockSession(ctx, user.ID, repoKey, sess.ID, now.Add(pullRequestLock), now)
	if err != nil {
		s.internalError(w, r, "failed to lock session", err)
		return
	}
	if !locked {
		writeError(w, http.StatusConflict, "a pull request is already being opened from this session")
		return
	}
	opened := false
	defer func() {
		if opened {
			return
		}
		unlock, cancel := context.WithTimeout(context.WithoutCancel(ctx), pullRequestFinish)
		defer cancel()
		if err := s.store.UnlockSession(unlock, user.ID, repoKey, sess.ID); err != nil {
			s.logger.ErrorContext(unlock, "failed to unlock session", "session_id", sess.ID, "error", err)
		}
	}()

	// a seal or reseal still running would finish after its change was read
	running, err := s.sealsRunning(ctx, sess.ID, now)
	if err != nil {
		s.internalError(w, r, "failed to read seal commands", err)
		return
	}
	if running {
		writeError(w, http.StatusConflict, "a seal or reseal is still running; open the pull request once it finishes")
		return
	}
	changes, err := s.store.Changes(ctx, sess.ID, true)
	if err != nil {
		s.internalError(w, r, "failed to read pending changes", err)
		return
	}
	if len(changes) == 0 {
		writeError(w, http.StatusConflict, "there are no pending changes to open a pull request with")
		return
	}
	// the text names each change's documents as they end up
	effective := store.Effective(changes)
	slices.SortFunc(effective, compareChanges)
	// values sealed with a key revoked since are not committed: the key may
	// be exposed
	revoked, err := s.store.RevokedKeys(ctx)
	if err != nil {
		s.internalError(w, r, "failed to read revoked keys", err)
		return
	}
	if stale := sealedWithRevokedKeys(effective, revoked); len(stale) > 0 {
		writeError(w, http.StatusConflict, fmt.Sprintf(
			"sealed with a key that has since been revoked: %s; seal these values again or remove them", strings.Join(stale, ", ")))
		return
	}
	text := s.pullRequestText(sess, user, effective)
	// values are written in the order they apply, so where changes of a
	// key overlap, the one that wins is written last: the newest, and a
	// seal over a reseal
	slices.SortStableFunc(changes, store.CompareRank)
	values := make([]repos.Value, len(changes))
	for i, c := range changes {
		targets := make([]repos.Target, len(c.Targets))
		for j, t := range c.Targets {
			targets[j] = repos.Target{Namespace: t.Namespace, Name: t.Name, Scope: t.Scope}
			if t.Index != nil {
				targets[j].Index = *t.Index
			}
		}
		// a reseal's documents are those whose value it resealed
		values[i] = repos.Value{Path: c.Path, Key: c.Key, Regions: c.Regions, Targets: targets, Ciphertexts: c.Ciphertexts, ByIndex: c.Resealed()}
	}
	branch := pullRequestBranch(s.env, user.Login, sess.ID)
	pr, err := s.repos.OpenPullRequest(ctx, user, sess.Owner, sess.Repo, repos.NewPullRequest{
		Commit:  sess.Commit,
		Branch:  branch,
		Title:   text.title,
		Body:    text.body,
		Message: text.message,
		Values:  values,
	})
	log := s.logger.With("env", s.env, "session_id", sess.ID, "user", user.Login, "user_id", user.ID,
		"repository", sess.Owner+"/"+sess.Repo, "commit", sess.Commit, "branch", branch)
	var fileErr *repos.FileError
	switch {
	case errors.As(err, &fileErr):
		log.WarnContext(ctx, "pull request refused", "event", "pr.failed", "error", err)
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	case errors.Is(err, githubapp.ErrBranchChanged):
		// an earlier attempt opened the pull request, and someone has
		// pushed to it since
		log.WarnContext(ctx, "pull request refused", "event", "pr.failed", "error", err)
		writeError(w, http.StatusConflict, "someone else has pushed to this session's pull request (branch "+branch+
			"), so it was left as it is; change the pull request on GitHub, or discard this session and seal the values in a new one")
		return
	case err != nil:
		log.WarnContext(ctx, "pull request failed", "event", "pr.failed", "error", err)
		s.repoError(w, r, err)
		return
	}
	opened = true

	end, cancelEnd := context.WithTimeout(context.WithoutCancel(ctx), pullRequestFinish)
	defer cancelEnd()
	if _, err := s.store.DeleteSession(end, user.ID, repoKey, sess.ID); err != nil {
		// the lock lapses and the session can be used again; opening a pull
		// request from it again updates this one
		log.ErrorContext(ctx, "failed to end session after opening its pull request", "error", err)
	}
	log.InfoContext(ctx, "pull request opened",
		"event", "pr.opened", "number", pr.Number, "url", pr.URL, "pr_commit", pr.Commit,
		"files", text.files, "changes", len(effective), "keys", text.keys)
	if text.resealed > 0 {
		s.recordSessionReseal(end, sess, user, pr, text, now, log)
	}
	httpserver.WriteJSON(w, http.StatusCreated, map[string]any{"pull_request": pullRequestView{
		Number:  pr.Number,
		URL:     pr.URL,
		Branch:  pr.Branch,
		Title:   text.title,
		Files:   text.files,
		Changes: len(effective),
	}})
}

// sealedWithRevokedKeys names the changes sealed with a revoked key, as
// "key (regions) in path".
func sealedWithRevokedKeys(changes []store.Change, revoked map[string]store.RevokedKey) []string {
	var out []string
	for _, c := range changes {
		if _, ok := revoked[c.Fingerprint]; !ok {
			continue
		}
		name := c.Key
		if len(c.Regions) > 0 {
			name += " (" + plain(strings.Join(c.Regions, ", ")) + ")"
		}
		out = append(out, name+" in "+plain(c.Path))
	}
	return out
}

// sealsRunning reports whether any seal or reseal of the session is queued
// or running.
func (s *Server) sealsRunning(ctx context.Context, sessionID string, now time.Time) (bool, error) {
	return s.sessionCommandRunning(ctx, sessionID, now, func(store.CommandRecord) bool { return true })
}

// sessionCommandRunning reports whether any command of the session that
// match selects is queued or running.
func (s *Server) sessionCommandRunning(ctx context.Context, sessionID string, now time.Time, match func(store.CommandRecord) bool) (bool, error) {
	for _, a := range s.currentRegistry().Agents {
		cmds, err := s.openCommands(ctx, a.ID, now)
		if err != nil {
			return false, err
		}
		for _, c := range cmds {
			if c.SessionID == sessionID && match(c) {
				return true, nil
			}
		}
	}
	return false, nil
}

// pullRequestBranch names a session's branch. There is one per session, so
// a session has one pull request at most.
func pullRequestBranch(env, login, sessionID string) string {
	return "sealer/" + env + "/" + strings.ToLower(login) + "-" + strings.ToLower(sessionID)
}

type prText struct {
	title, body, message string
	files                int
	keys                 []string
	// resealed counts the values reseals moved, in resealFiles files, off
	// fromKeys
	resealed, resealFiles int
	fromKeys              []string
}

// recordSessionReseal records a pull request opened from a session with
// reseal changes among the reseal pull requests. The pull request is open
// whatever happens here.
func (s *Server) recordSessionReseal(ctx context.Context, sess store.Session, user *userauth.User, pr githubapp.PullRequest, text prText, now time.Time, log *slog.Logger) {
	rec := store.ResealPullRequest{
		Repo:        sess.Owner + "/" + sess.Repo,
		Number:      pr.Number,
		URL:         pr.URL,
		Title:       text.title,
		Branch:      pr.Branch,
		State:       store.PullOpen,
		Source:      store.SourceSession,
		RequestedBy: user.Login,
		OpenedAt:    now,
		CheckedAt:   now,
		Values:      text.resealed,
		Files:       text.resealFiles,
		FromKeys:    text.fromKeys,
	}
	if err := s.store.PutResealPullRequest(ctx, rec); err != nil {
		log.ErrorContext(ctx, "failed to record a reseal pull request", "number", pr.Number, "error", err)
		return
	}
	log.InfoContext(ctx, "reseal pull request opened",
		"event", "reseal.pr_opened", "source", store.SourceSession, "number", pr.Number, "url", pr.URL,
		"values", text.resealed, "files", text.resealFiles, "from_keys", text.fromKeys)
}

// pullRequestText writes a pull request's title, description and commit
// message from the changes as they apply. They name files, keys, regions
// and documents, never values or ciphertexts. Values a reseal moved onto
// the env key are listed apart from values sealed in the session.
func (s *Server) pullRequestText(sess store.Session, user *userauth.User, changes []store.Change) prText {
	var sealed, resealed []store.Change
	for _, c := range changes {
		if c.Resealed() {
			resealed = append(resealed, c)
		} else {
			sealed = append(sealed, c)
		}
	}
	text := prText{}
	var paths, resealPaths []string
	keysByPath := map[string][]string{}
	resealKeysByPath := map[string][]string{}
	for _, c := range sealed {
		if _, ok := keysByPath[c.Path]; !ok {
			paths = append(paths, c.Path)
		}
		key := c.Key
		if len(c.Regions) > 0 {
			// changes stored before regions were checked may hold any text
			key += " (" + plain(strings.Join(c.Regions, ", ")) + ")"
		}
		keysByPath[c.Path] = append(keysByPath[c.Path], key)
		text.keys = append(text.keys, c.Key)
	}
	for _, c := range resealed {
		if _, ok := resealKeysByPath[c.Path]; !ok {
			resealPaths = append(resealPaths, c.Path)
		}
		resealKeysByPath[c.Path] = append(resealKeysByPath[c.Path], c.Key)
		text.keys = append(text.keys, c.Key)
		text.resealed += len(c.Targets)
		for _, fp := range c.ResealedFrom {
			if !slices.Contains(text.fromKeys, fp) {
				text.fromKeys = append(text.fromKeys, fp)
			}
		}
	}
	slices.Sort(text.fromKeys)
	text.resealFiles = len(resealPaths)
	allPaths := slices.Clone(paths)
	for _, p := range resealPaths {
		if !slices.Contains(allPaths, p) {
			allPaths = append(allPaths, p)
		}
	}
	text.files = len(allPaths)
	text.title = s.pullRequestTitle(sealed, paths, text.resealed, allPaths)

	var b strings.Builder
	fmt.Fprintf(&b, "Sealed for the **%s** env with k8s-sealed-secrets-sealer, as requested by @%s.\n\n", s.env, user.Login)
	if len(sealed) > 0 {
		b.WriteString("| File | Key | Documents | Sealed with |\n| --- | --- | --- | --- |\n")
		regional := false
		for _, c := range sealed {
			key := code(c.Key)
			if len(c.Regions) > 0 {
				regional = true
				regions := make([]string, len(c.Regions))
				for i, r := range c.Regions {
					regions[i] = code(r)
				}
				key += " in " + strings.Join(regions, ", ")
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", code(c.Path), key, documents(c.Targets), code(shortFingerprint(c.Fingerprint)))
		}
		if regional {
			fmt.Fprintf(&b, "\nEach value was sealed once for each %s document listed: every one in its file, or those in the regions named. Only `spec.encryptedData` changed. Based on `%s` at %s.\n",
				s.env, sess.Branch, sess.Commit)
		} else {
			fmt.Fprintf(&b, "\nEach value was sealed once for every %s document in its file; only `spec.encryptedData` changed. Based on `%s` at %s.\n",
				s.env, sess.Branch, sess.Commit)
		}
	}
	if len(resealed) > 0 {
		if len(sealed) > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "Resealed: %s moved off older keys onto the env key, unchanged.\n\n", plural(text.resealed, "value"))
		b.WriteString("| File | Key | Documents | From | To |\n| --- | --- | --- | --- | --- |\n")
		for _, c := range resealed {
			from := make([]string, len(c.ResealedFrom))
			for i, fp := range c.ResealedFrom {
				from[i] = code(shortFingerprint(fp))
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", code(c.Path), code(c.Key), documents(c.Targets),
				strings.Join(from, ", "), code(shortFingerprint(c.Fingerprint)))
		}
		fmt.Fprintf(&b, "\n%s Only `spec.encryptedData` changed. Based on `%s` at %s.\n", resealNote, sess.Branch, sess.Commit)
	}

	var m strings.Builder
	m.WriteString(text.title + "\n\n")
	for _, p := range paths {
		fmt.Fprintf(&m, "%s: %s\n", plain(p), strings.Join(keysByPath[p], ", "))
	}
	if len(resealPaths) > 0 {
		if len(paths) > 0 {
			m.WriteString("\n")
		}
		m.WriteString("Resealed onto the env key:\n")
		for _, p := range resealPaths {
			fmt.Fprintf(&m, "%s: %s\n", plain(p), strings.Join(resealKeysByPath[p], ", "))
		}
	}
	fmt.Fprintf(&m, "\nRequested-by: %s <%d+%s@users.noreply.github.com>\n", user.Login, user.ID, user.Login)
	text.body, text.message = b.String(), m.String()
	return text
}

// resealNote says what resealing is not, wherever it is offered.
const resealNote = "Resealing moves values off older keys so those keys can be deleted once nothing uses them. It does not rotate them: git history keeps the old ciphertext, so a value sealed with a key that may be exposed must be sealed again with a new value."

// pullRequestTitle names what a session's pull request seals and reseals.
func (s *Server) pullRequestTitle(sealed []store.Change, paths []string, resealed int, allPaths []string) string {
	values := plural(len(sealed), "value")
	if resealed == 0 {
		title := fmt.Sprintf("Seal %s in %s for %s", values, plural(len(paths), "file"), s.env)
		switch {
		case len(sealed) == 1:
			title = fmt.Sprintf("Seal %s in %s for %s", sealed[0].Key, plain(sealed[0].Path), s.env)
		case len(paths) == 1:
			title = fmt.Sprintf("Seal %s in %s for %s", values, plain(paths[0]), s.env)
		}
		if len(title) > maxTitleLength {
			title = fmt.Sprintf("Seal %s in %s for %s", values, plural(len(paths), "file"), s.env)
		}
		return title
	}
	in := plural(len(allPaths), "file")
	if len(allPaths) == 1 && len(plain(allPaths[0])) <= maxTitleLength/2 {
		in = plain(allPaths[0])
	}
	if len(sealed) == 0 {
		return fmt.Sprintf("Reseal %s in %s for %s", plural(resealed, "value"), in, s.env)
	}
	return fmt.Sprintf("Seal %s and reseal %s in %s for %s", values, plural(resealed, "value"), in, s.env)
}

// documents names a change's documents for a table cell.
func documents(targets []store.Target) string {
	docs := make([]string, len(targets))
	for i, t := range targets {
		docs[i] = code(t.Namespace + "/" + t.Name)
	}
	return strings.Join(docs, ", ")
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// plain replaces control characters, which file names may hold, so a name
// stays on one line.
func plain(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '�'
		}
		return r
	}, s)
}

// code writes s as a Markdown code span that is safe in a table cell.
func code(s string) string {
	s = strings.ReplaceAll(plain(s), "|", `\|`)
	fence := "`"
	for strings.Contains(s, fence) {
		fence += "`"
	}
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		s = " " + s + " "
	}
	return fence + s + fence
}

// shortFingerprint shortens SHA256:<base64> to its first 12 characters
// after the prefix.
func shortFingerprint(fp string) string {
	if rest, ok := strings.CutPrefix(fp, "SHA256:"); ok && len(rest) > 12 {
		return "SHA256:" + rest[:12]
	}
	return fp
}

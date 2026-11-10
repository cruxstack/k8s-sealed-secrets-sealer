package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

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

	// a seal still running would finish after its change was read
	running, err := s.sealsRunning(ctx, sess.ID, now)
	if err != nil {
		s.internalError(w, r, "failed to read seal commands", err)
		return
	}
	if running {
		writeError(w, http.StatusConflict, "a seal is still running; open the pull request once it finishes")
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
	text := s.pullRequestText(sess, user, effective)
	// values are written in the order they were sealed, so where changes of
	// a key overlap, the newest wins
	slices.SortFunc(changes, func(a, b store.Change) int { return strings.Compare(a.CommandID, b.CommandID) })
	values := make([]repos.Value, len(changes))
	for i, c := range changes {
		targets := make([]repos.Target, len(c.Targets))
		for j, t := range c.Targets {
			targets[j] = repos.Target{Namespace: t.Namespace, Name: t.Name, Scope: t.Scope}
		}
		values[i] = repos.Value{Path: c.Path, Key: c.Key, Regions: c.Regions, Targets: targets, Ciphertexts: c.Ciphertexts}
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
	httpserver.WriteJSON(w, http.StatusCreated, map[string]any{"pull_request": pullRequestView{
		Number:  pr.Number,
		URL:     pr.URL,
		Branch:  pr.Branch,
		Title:   text.title,
		Files:   text.files,
		Changes: len(effective),
	}})
}

// sealsRunning reports whether any seal of the session is queued or being
// sealed.
func (s *Server) sealsRunning(ctx context.Context, sessionID string, now time.Time) (bool, error) {
	for _, a := range s.currentRegistry().Agents {
		cmds, err := s.openCommands(ctx, a.ID, now)
		if err != nil {
			return false, err
		}
		for _, c := range cmds {
			if c.SessionID == sessionID {
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
}

// pullRequestText writes a pull request's title, description and commit
// message from the changes as they apply. They name files, keys, regions
// and documents, never values or ciphertexts.
func (s *Server) pullRequestText(sess store.Session, user *userauth.User, changes []store.Change) prText {
	var paths []string
	keysByPath := map[string][]string{}
	var keys []string
	for _, c := range changes {
		if _, ok := keysByPath[c.Path]; !ok {
			paths = append(paths, c.Path)
		}
		key := c.Key
		if len(c.Regions) > 0 {
			// changes stored before regions were checked may hold any text
			key += " (" + plain(strings.Join(c.Regions, ", ")) + ")"
		}
		keysByPath[c.Path] = append(keysByPath[c.Path], key)
		keys = append(keys, c.Key)
	}
	values := plural(len(changes), "value")

	title := fmt.Sprintf("Seal %s in %s for %s", values, plural(len(paths), "file"), s.env)
	switch {
	case len(changes) == 1:
		title = fmt.Sprintf("Seal %s in %s for %s", changes[0].Key, plain(changes[0].Path), s.env)
	case len(paths) == 1:
		title = fmt.Sprintf("Seal %s in %s for %s", values, plain(paths[0]), s.env)
	}
	if len(title) > maxTitleLength {
		title = fmt.Sprintf("Seal %s in %s for %s", values, plural(len(paths), "file"), s.env)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Sealed for the **%s** env with k8s-sealed-secrets-sealer, as requested by @%s.\n\n", s.env, user.Login)
	b.WriteString("| File | Key | Documents | Sealed with |\n| --- | --- | --- | --- |\n")
	regional := false
	for _, c := range changes {
		docs := make([]string, len(c.Targets))
		for i, t := range c.Targets {
			docs[i] = code(t.Namespace + "/" + t.Name)
		}
		key := code(c.Key)
		if len(c.Regions) > 0 {
			regional = true
			regions := make([]string, len(c.Regions))
			for i, r := range c.Regions {
				regions[i] = code(r)
			}
			key += " in " + strings.Join(regions, ", ")
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", code(c.Path), key, strings.Join(docs, ", "), code(shortFingerprint(c.Fingerprint)))
	}
	if regional {
		fmt.Fprintf(&b, "\nEach value was sealed once for each %s document listed: every one in its file, or those in the regions named. Only `spec.encryptedData` changed. Based on `%s` at %s.\n",
			s.env, sess.Branch, sess.Commit)
	} else {
		fmt.Fprintf(&b, "\nEach value was sealed once for every %s document in its file; only `spec.encryptedData` changed. Based on `%s` at %s.\n",
			s.env, sess.Branch, sess.Commit)
	}

	var m strings.Builder
	m.WriteString(title + "\n\n")
	for _, p := range paths {
		fmt.Fprintf(&m, "%s: %s\n", plain(p), strings.Join(keysByPath[p], ", "))
	}
	fmt.Fprintf(&m, "\nRequested-by: %s <%d+%s@users.noreply.github.com>\n", user.Login, user.ID, user.Login)
	return prText{title: title, body: b.String(), message: m.String(), files: len(paths), keys: keys}
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

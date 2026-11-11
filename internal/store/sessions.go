package store

import (
	"errors"
	"strings"
	"time"
)

// Session errors.
var (
	// ErrTooManySessions is returned when a user already has the most live
	// sessions allowed.
	ErrTooManySessions = errors.New("too many open sessions")
	// ErrTooManyChanges is returned when a session already holds, or is
	// about to hold, the most pending changes allowed.
	ErrTooManyChanges = errors.New("too many pending changes")
	// ErrSessionBusy is returned when a session is locked while a pull
	// request is opened from it.
	ErrSessionBusy = errors.New("a pull request is being opened from this session")
)

// Session is one user's set of pending changes to one repository, based on
// a commit of its default branch. A user has at most one live session per
// repository.
type Session struct {
	ID        string    `dynamodbav:"session_id"`
	UserID    int64     `dynamodbav:"user_id"`
	UserLogin string    `dynamodbav:"user_login"`
	Owner     string    `dynamodbav:"owner"`
	Repo      string    `dynamodbav:"repo"`
	Branch    string    `dynamodbav:"branch"`
	Commit    string    `dynamodbav:"commit"`
	CreatedAt time.Time `dynamodbav:"created_at"`
	UsedAt    time.Time `dynamodbav:"used_at"`
	// ExpiresAt ends the session when it goes unused; using it moves this
	// on, but never past EndsAt.
	ExpiresAt time.Time `dynamodbav:"session_expires_at"`
	// EndsAt is the latest a session lasts. Its seals and pending changes
	// are kept until then.
	EndsAt time.Time `dynamodbav:"session_ends_at"`
	// SubmitDeadline (epoch milliseconds) is set while a pull request is
	// opened from the session: until then, or until the lock is released,
	// the session cannot be used.
	SubmitDeadline int64 `dynamodbav:"submit_deadline,omitempty"`
}

// reserveChange decides a ReserveChange for both stores. reserved maps the
// places seals hold (placeKey) to when each lapses (epoch milliseconds). It
// returns the places to keep, the seal's among them.
func reserveChange(reserved map[string]int64, changeID, sealID string, existing []string, limit int, until, now time.Time) (map[string]int64, error) {
	held := map[string]bool{}
	for _, id := range existing {
		held[id] = true
	}
	kept := livePlaces(reserved, now)
	for place := range kept {
		held[placeChange(place)] = true
	}
	if !held[changeID] && len(held) >= limit {
		return nil, ErrTooManyChanges
	}
	place := placeKey(changeID, sealID)
	kept[place] = max(kept[place], until.UnixMilli())
	return kept, nil
}

// releaseChange decides a ReleaseChange for both stores: the places to
// keep, without the seal's, and whether it held one.
func releaseChange(reserved map[string]int64, changeID, sealID string, now time.Time) (map[string]int64, bool) {
	kept := livePlaces(reserved, now)
	place := placeKey(changeID, sealID)
	_, held := kept[place]
	delete(kept, place)
	return kept, held
}

func livePlaces(reserved map[string]int64, now time.Time) map[string]int64 {
	kept := map[string]int64{}
	for place, lapses := range reserved {
		if lapses > now.UnixMilli() {
			kept[place] = lapses
		}
	}
	return kept
}

// placeKey names the place one seal holds for its change, so a seal can
// release its own and not another's of the same change.
func placeKey(changeID, sealID string) string { return changeID + "/" + sealID }

// placeChange is the change a place is held for. Places held before seals
// were named in them are the change ID alone.
func placeChange(place string) string {
	id, _, _ := strings.Cut(place, "/")
	return id
}

// Live reports whether the session is still open at now.
func (s Session) Live(now time.Time) bool { return now.Before(s.ExpiresAt) }

// Locked reports whether a pull request is being opened from the session.
func (s Session) Locked(now time.Time) bool { return s.SubmitDeadline > now.UnixMilli() }

// RepoKey identifies a repository in session keys. GitHub names are case
// insensitive.
func RepoKey(owner, repo string) string { return strings.ToLower(owner + "/" + repo) }

// Target is one SealedSecret document a seal writes to.
type Target struct {
	// Index is the document's position in the file at the session's
	// commit, which identifies it. Nil for changes stored before it was
	// recorded; those are told apart by region, namespace and name.
	Index     *int   `dynamodbav:"index,omitempty"`
	Namespace string `dynamodbav:"namespace"`
	Name      string `dynamodbav:"name"`
	Scope     string `dynamodbav:"scope"`
	Region    string `dynamodbav:"region,omitempty"`
}

// Seal is a seal requested in a session: which command carries it and to
// which agent, so its progress can be looked up.
type Seal struct {
	SessionID   string `dynamodbav:"session_id"`
	CommandID   string `dynamodbav:"command_id"`
	AgentID     string `dynamodbav:"agent_id"`
	Path        string `dynamodbav:"path"`
	Key         string `dynamodbav:"key"`
	Fingerprint string `dynamodbav:"fingerprint"`
	// Regions limits the seal to the file's documents in these regions;
	// empty seals it for every document.
	Regions   []string  `dynamodbav:"regions,omitempty"`
	Targets   []Target  `dynamodbav:"targets"`
	UserID    int64     `dynamodbav:"user_id"`
	UserLogin string    `dynamodbav:"user_login"`
	CreatedAt time.Time `dynamodbav:"created_at"`
	// ExpiresAt is the session's EndsAt.
	ExpiresAt time.Time `dynamodbav:"seal_expires_at"`
}

// Change is a pending change: a value sealed for the target documents of a
// file, waiting to be committed. There is one per file, key and regions in a
// session; sealing the same key into the same file for the same regions
// again replaces it. Changes of one key may overlap, and the newest wins for
// each document (see Effective).
type Change struct {
	SessionID   string `dynamodbav:"session_id"`
	ID          string `dynamodbav:"change_id"`
	Path        string `dynamodbav:"path"`
	Key         string `dynamodbav:"key"`
	CommandID   string `dynamodbav:"command_id"`
	AgentID     string `dynamodbav:"agent_id"`
	Fingerprint string `dynamodbav:"fingerprint"`
	// Regions is what the seal was limited to; empty for every document.
	Regions []string `dynamodbav:"regions,omitempty"`
	Targets []Target `dynamodbav:"targets"`
	// Ciphertexts holds one ciphertext per target, in order. It is stored
	// apart from Targets so listings can leave it out. Nil when not read.
	Ciphertexts []string  `dynamodbav:"ciphertexts,omitempty"`
	UserID      int64     `dynamodbav:"user_id"`
	UserLogin   string    `dynamodbav:"user_login"`
	SealedAt    time.Time `dynamodbav:"sealed_at"`
	// ExpiresAt is the session's EndsAt.
	ExpiresAt time.Time `dynamodbav:"change_expires_at"`
}

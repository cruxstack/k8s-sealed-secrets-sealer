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

// reserveChanges decides a ReserveChanges for both stores. reserved maps
// the places seals hold (placeKey) to when each lapses (epoch
// milliseconds); places maps the changes to hold places for to the seal
// (or reseal command) each is for. It returns the places to keep, the new
// ones among them.
func reserveChanges(reserved map[string]int64, places map[string]string, existing []string, limit int, until, now time.Time) (map[string]int64, error) {
	held := map[string]bool{}
	for _, id := range existing {
		held[id] = true
	}
	kept := livePlaces(reserved, now)
	for place := range kept {
		held[placeChange(place)] = true
	}
	added := 0
	for changeID := range places {
		if !held[changeID] {
			added++
		}
	}
	if added > 0 && len(held)+added > limit {
		return nil, ErrTooManyChanges
	}
	for changeID, sealID := range places {
		place := placeKey(changeID, sealID)
		kept[place] = max(kept[place], until.UnixMilli())
	}
	return kept, nil
}

// releaseChanges decides a ReleaseChanges for both stores: the places to
// keep, without those given, and whether any was held.
func releaseChanges(reserved map[string]int64, places map[string]string, now time.Time) (map[string]int64, bool) {
	kept := livePlaces(reserved, now)
	held := false
	for changeID, sealID := range places {
		place := placeKey(changeID, sealID)
		if _, ok := kept[place]; ok {
			held = true
		}
		delete(kept, place)
	}
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
	// Regions are the document's regions.
	Regions []string `dynamodbav:"regions,omitempty"`
	// Region is the one region of a target stored before documents could
	// list several; read through RegionList.
	Region string `dynamodbav:"region,omitempty"`
}

// RegionList returns the target's regions, whenever it was stored.
func (t Target) RegionList() []string {
	if len(t.Regions) == 0 && t.Region != "" {
		return []string{t.Region}
	}
	return t.Regions
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

// Kinds of pending change.
const (
	// ChangeSeal is a value sealed in the session; changes stored before
	// kinds were recorded are seals.
	ChangeSeal = "seal"
	// ChangeReseal is a file's values moved onto the env key, for the
	// documents whose value was resealed.
	ChangeReseal = "reseal"
)

// Change is a pending change: a value sealed for the target documents of a
// file, waiting to be committed. There is one per file, key and regions in a
// session; sealing the same key into the same file for the same regions
// again replaces it. A reseal makes one per file and key, of its own.
// Changes of one key may overlap, and the newest wins for each document (see
// Effective).
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
	// Kind is ChangeSeal (also when empty) or ChangeReseal. A reseal's
	// targets are the documents, by position, whose value it resealed;
	// ResealedFrom names the keys those values came off, and Fingerprint
	// the env key they are on now.
	Kind         string   `dynamodbav:"kind,omitempty"`
	ResealedFrom []string `dynamodbav:"resealed_from,omitempty"`
}

// Resealed reports whether the change is a reseal.
func (c Change) Resealed() bool { return c.Kind == ChangeReseal }

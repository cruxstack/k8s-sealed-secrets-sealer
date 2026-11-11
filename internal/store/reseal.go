package store

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Resealing moves sealed values off older keys onto the env key
// (docs/design.md, "Resealing"). These are the records it keeps.

// ResealRetention is how long finished runs, and merged or closed reseal
// pull requests, are kept.
const ResealRetention = 180 * 24 * time.Hour

// ResealFailure is one value that could not be resealed. It names where the
// value is, never what it is.
type ResealFailure struct {
	Path     string `dynamodbav:"path,omitempty" json:"path,omitempty"`
	Key      string `dynamodbav:"key" json:"key"`
	Document int    `dynamodbav:"document" json:"document"`
	Region   string `dynamodbav:"region,omitempty" json:"region,omitempty"`
	Error    string `dynamodbav:"error" json:"error"`
}

// ResealCounts counts values by what resealing did with them.
type ResealCounts struct {
	Resealed int `dynamodbav:"resealed" json:"resealed"`
	Current  int `dynamodbav:"current" json:"current"`
	Failed   int `dynamodbav:"failed" json:"failed"`
}

// Add adds o's counts.
func (c *ResealCounts) Add(o ResealCounts) {
	c.Resealed += o.Resealed
	c.Current += o.Current
	c.Failed += o.Failed
}

// FileReseal is a file's values sent for resealing in a session: which
// commands carry them and to which agent, and what each command did, so
// its progress can be looked up. Its results become pending changes.
type FileReseal struct {
	SessionID string `dynamodbav:"session_id"`
	ID        string `dynamodbav:"reseal_id"`
	Path      string `dynamodbav:"path"`
	AgentID   string `dynamodbav:"agent_id"`
	// EnvKey is the key the values move to.
	EnvKey    string    `dynamodbav:"env_key"`
	UserID    int64     `dynamodbav:"user_id"`
	UserLogin string    `dynamodbav:"user_login"`
	CreatedAt time.Time `dynamodbav:"created_at"`
	// ExpiresAt is the session's EndsAt.
	ExpiresAt time.Time `dynamodbav:"reseal_expires_at"`
	// Documents are the file's documents for the env whose values were
	// sent, by their position in the file.
	Documents []Target `dynamodbav:"documents"`
	// Commands carry the values, each the values of whole keys.
	Commands []FileResealCommand `dynamodbav:"commands"`
	// Total counts the values of the file's documents for the env, Pending
	// those left out because a pending change of the session sets them, and
	// Failures those that failed before any was sent.
	Total    int             `dynamodbav:"total"`
	Pending  int             `dynamodbav:"pending"`
	Failures []ResealFailure `dynamodbav:"failures,omitempty"`
	// Outcomes holds what each finished command did, by command ID.
	Outcomes map[string]ResealOutcome `dynamodbav:"outcomes"`
}

// FileResealCommand is one reseal.v1 command of a FileReseal: the keys
// whose values it carries, and its items' IDs.
type FileResealCommand struct {
	ID    string   `dynamodbav:"id"`
	Keys  []string `dynamodbav:"keys"`
	Items []string `dynamodbav:"items"`
}

// ResealOutcome is what one reseal.v1 command of a file reseal did.
type ResealOutcome struct {
	// Status is the command's: CommandSucceeded or CommandFailed.
	Status     string          `dynamodbav:"status"`
	Error      string          `dynamodbav:"error,omitempty"`
	Counts     ResealCounts    `dynamodbav:"counts"`
	Failures   []ResealFailure `dynamodbav:"failures,omitempty"`
	ChangeIDs  []string        `dynamodbav:"change_ids,omitempty"`
	FinishedAt time.Time       `dynamodbav:"finished_at"`
}

// Reseal pull request states and sources.
const (
	PullOpen   = "open"
	PullMerged = "merged"
	PullClosed = "closed"

	SourceSchedule = "schedule"
	SourceSession  = "session"
)

// ResealPullRequest is a pull request with resealed values: one a run
// opened, or one opened from a session with reseal changes.
type ResealPullRequest struct {
	// Repo is "owner/name" as GitHub names it.
	Repo   string `dynamodbav:"repo"`
	Number int    `dynamodbav:"number"`
	URL    string `dynamodbav:"url"`
	Title  string `dynamodbav:"title"`
	Branch string `dynamodbav:"branch"`
	// State is PullOpen, PullMerged or PullClosed.
	State string `dynamodbav:"state"`
	// Source is SourceSchedule (with the schedule and run) or
	// SourceSession.
	Source       string     `dynamodbav:"source"`
	ScheduleID   string     `dynamodbav:"schedule_id,omitempty"`
	ScheduleName string     `dynamodbav:"schedule_name,omitempty"`
	RunID        string     `dynamodbav:"run_id,omitempty"`
	RequestedBy  string     `dynamodbav:"requested_by"`
	OpenedAt     time.Time  `dynamodbav:"opened_at"`
	MergedAt     *time.Time `dynamodbav:"merged_at,omitempty"`
	ClosedAt     *time.Time `dynamodbav:"closed_at,omitempty"`
	// CheckedAt is when its state was last read from GitHub.
	CheckedAt time.Time `dynamodbav:"checked_at"`
	Values    int       `dynamodbav:"values"`
	Files     int       `dynamodbav:"files"`
	// FromKeys are the fingerprints of the keys it moves values off.
	FromKeys []string `dynamodbav:"from_keys,omitempty"`
}

// RepoKey is the pull request's repository, as keys name it.
func (p ResealPullRequest) RepoKey() string { return strings.ToLower(p.Repo) }

// endedAt is when a merged or closed pull request ended.
func (p ResealPullRequest) endedAt() time.Time {
	switch {
	case p.MergedAt != nil:
		return *p.MergedAt
	case p.ClosedAt != nil:
		return *p.ClosedAt
	}
	return p.CheckedAt
}

// check validates a pull request before it is stored.
func (p ResealPullRequest) check() error {
	switch {
	case p.Repo == "" || p.Number <= 0:
		return errors.New("a repository and number are required")
	case p.State != PullOpen && p.State != PullMerged && p.State != PullClosed:
		return fmt.Errorf("unknown state %q", p.State)
	}
	return nil
}

// pullSortKey names a reseal pull request in the RESEAL partition: open ones
// apart from merged and closed ones, so listing the open ones reads only
// those, however many ended ones are kept. Numbers are padded so a
// repository's pull requests sort by number.
func pullSortKey(open bool, repoKey string, number int) string {
	state := pullDonePrefix
	if open {
		state = pullOpenPrefix
	}
	return fmt.Sprintf("%s%s#%010d", state, repoKey, number)
}

const (
	pullOpenPrefix = "PR#OPEN#"
	pullDonePrefix = "PR#DONE#"
)

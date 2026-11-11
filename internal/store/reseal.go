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
	// Failed those that failed before any was sent; Failures names the
	// first of those, at most 50, so the item stays small.
	Total    int             `dynamodbav:"total"`
	Pending  int             `dynamodbav:"pending"`
	Failed   int             `dynamodbav:"failed"`
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

// Errors of schedules and runs.
var (
	// ErrTooManySchedules is returned when an env has the most schedules
	// allowed.
	ErrTooManySchedules = errors.New("too many reseal schedules")
	// ErrRunActive is returned when a schedule's run is queued or running
	// already.
	ErrRunActive = errors.New("a run of this schedule is active")
	// ErrScheduleChanged is returned when a schedule was deleted, or its
	// next run moved, since it was read.
	ErrScheduleChanged = errors.New("the schedule changed")
)

// ResealSchedule reseals the values in a scope every IntervalDays: listed
// repositories, and every repository the GitHub App can reach of the listed
// orgs.
type ResealSchedule struct {
	ID           string   `dynamodbav:"schedule_id"`
	Name         string   `dynamodbav:"name"`
	Repos        []string `dynamodbav:"repos"`
	Orgs         []string `dynamodbav:"orgs"`
	IntervalDays int      `dynamodbav:"interval_days"`
	Enabled      bool     `dynamodbav:"enabled"`
	// NextRunAt is when the tick starts its next run; nil while disabled.
	NextRunAt *time.Time `dynamodbav:"next_run_at,omitempty"`
	// CreatedBy and CreatedByID name who created it: its pull requests
	// name them as who requested them.
	CreatedBy   string     `dynamodbav:"created_by"`
	CreatedByID int64      `dynamodbav:"created_by_id"`
	CreatedAt   time.Time  `dynamodbav:"created_at"`
	UpdatedBy   string     `dynamodbav:"updated_by,omitempty"`
	UpdatedAt   *time.Time `dynamodbav:"updated_at,omitempty"`
	// ActiveRunID is the run queued or running, at most one; LastRunID the
	// latest run, active or not.
	ActiveRunID string `dynamodbav:"active_run_id,omitempty"`
	LastRunID   string `dynamodbav:"last_run_id,omitempty"`
}

// Run triggers and statuses.
const (
	TriggerSchedule = "schedule"
	TriggerManual   = "manual"

	RunQueued    = "queued"
	RunRunning   = "running"
	RunSucceeded = "succeeded"
	RunPartial   = "partial"
	RunFailed    = "failed"
	RunCancelled = "cancelled"
)

// ResealRun is one execution of a schedule: its summary, and how far it
// got. Its repositories are ResealRunRepo records.
type ResealRun struct {
	ID           string `dynamodbav:"run_id"`
	ScheduleID   string `dynamodbav:"schedule_id"`
	ScheduleName string `dynamodbav:"schedule_name"`
	// CreatedBy and CreatedByID are the schedule's creator, whom the run's
	// pull requests name.
	CreatedBy   string `dynamodbav:"created_by"`
	CreatedByID int64  `dynamodbav:"created_by_id"`
	// Repos and Orgs are the schedule's scope when the run started.
	Repos       []string   `dynamodbav:"repos"`
	Orgs        []string   `dynamodbav:"orgs"`
	Trigger     string     `dynamodbav:"trigger"`
	RequestedBy string     `dynamodbav:"requested_by"`
	Status      string     `dynamodbav:"status"`
	StartedAt   time.Time  `dynamodbav:"started_at"`
	FinishedAt  *time.Time `dynamodbav:"finished_at,omitempty"`
	CancelledBy string     `dynamodbav:"cancelled_by,omitempty"`
	Error       string     `dynamodbav:"error,omitempty"`

	// Discovered is set once its repositories are recorded; Total counts
	// them.
	Discovered bool `dynamodbav:"discovered"`
	Total      int  `dynamodbav:"total"`
	// Outcomes counts the repositories done, by outcome.
	Outcomes     ResealRunOutcomes `dynamodbav:"outcomes"`
	Values       ResealCounts      `dynamodbav:"values"`
	PullRequests int               `dynamodbav:"pull_requests"`
	// Cursor is the key of the last repository started, in key order;
	// InFlight the keys of those started and not done.
	Cursor   string   `dynamodbav:"cursor,omitempty"`
	InFlight []string `dynamodbav:"in_flight,omitempty"`
	// LeaseUntil (epoch milliseconds) is set while a tick advances the run.
	LeaseUntil int64 `dynamodbav:"lease_until,omitempty"`
	// ProgressAt is when a tick last moved the run on; a run that makes no
	// progress for long fails, so its schedule can run again.
	ProgressAt *time.Time `dynamodbav:"progress_at,omitempty"`
}

// ResealRunOutcomes counts a run's repositories that are done, by outcome.
type ResealRunOutcomes struct {
	Opened    int `dynamodbav:"opened"`
	Unchanged int `dynamodbav:"unchanged"`
	Skipped   int `dynamodbav:"skipped"`
	Failed    int `dynamodbav:"failed"`
}

// Done counts the repositories done.
func (o ResealRunOutcomes) Done() int { return o.Opened + o.Unchanged + o.Skipped + o.Failed }

// Active reports whether the run is queued or running.
func (r ResealRun) Active() bool { return r.Status == RunQueued || r.Status == RunRunning }

// Repository statuses in a run.
const (
	RepoPending   = "pending"
	RepoResealing = "resealing"
	RepoOpening   = "opening"
	RepoOpened    = "opened"
	RepoUnchanged = "unchanged"
	RepoSkipped   = "skipped"
	RepoFailed    = "failed"
)

// ResealRunRepo is one repository of a run, as people see it.
type ResealRunRepo struct {
	RunID string `dynamodbav:"run_id"`
	// Key is the repository's RepoKey; Repo names it as GitHub does.
	Key         string          `dynamodbav:"repo_key"`
	Repo        string          `dynamodbav:"repo"`
	Status      string          `dynamodbav:"status"`
	Reason      string          `dynamodbav:"reason,omitempty"`
	Files       int             `dynamodbav:"files"`
	Values      ResealCounts    `dynamodbav:"values"`
	PullRequest *ResealRunPull  `dynamodbav:"pull_request,omitempty"`
	Failures    []ResealFailure `dynamodbav:"failures,omitempty"`
	FromKeys    []string        `dynamodbav:"from_keys,omitempty"`
	UpdatedAt   time.Time       `dynamodbav:"updated_at"`
}

// Done reports whether the repository's part of the run is over.
func (r ResealRunRepo) Done() bool {
	switch r.Status {
	case RepoOpened, RepoUnchanged, RepoSkipped, RepoFailed:
		return true
	}
	return false
}

// ResealRunPull is the pull request a run opened in a repository.
type ResealRunPull struct {
	Number int    `dynamodbav:"number" json:"number"`
	URL    string `dynamodbav:"url" json:"url"`
}

// ResealWork is what a run needs to carry on with a repository: the commit
// it read, the files it found and the commands it queued. It is apart from
// ResealRunRepo, which run views read for every repository.
type ResealWork struct {
	RunID  string `dynamodbav:"run_id"`
	Key    string `dynamodbav:"repo_key"`
	Owner  string `dynamodbav:"owner"`
	Name   string `dynamodbav:"name"`
	Branch string `dynamodbav:"branch"`
	Commit string `dynamodbav:"commit"`
	// Candidates are the files the discovery globs match at Commit; Next
	// is the first not read yet.
	Candidates []ResealFile `dynamodbav:"candidates"`
	Next       int          `dynamodbav:"next"`
	// Files are those with documents for the env, in the order read; a
	// value names its file by its place here.
	Files    []ResealFile    `dynamodbav:"files"`
	Commands []ResealCommand `dynamodbav:"commands"`
	// Attempts counts the tries to open its pull request that failed;
	// LastError is the last one's.
	Attempts  int       `dynamodbav:"attempts"`
	LastError string    `dynamodbav:"last_error,omitempty"`
	UpdatedAt time.Time `dynamodbav:"updated_at"`
}

// ResealFile is a file of a run's repository at the commit it read.
type ResealFile struct {
	Path string `dynamodbav:"path"`
	SHA  string `dynamodbav:"sha"`
	Mode string `dynamodbav:"mode"`
}

// ResealCommand is a reseal.v1 command a run queued.
type ResealCommand struct {
	ID        string    `dynamodbav:"id"`
	AgentID   string    `dynamodbav:"agent_id"`
	Items     int       `dynamodbav:"items"`
	ExpiresAt time.Time `dynamodbav:"expires_at"`
}

// ResealBatch is what one of a run's reseal.v1 commands did with each value
// it carried: kept until the run's pull request is opened from it.
type ResealBatch struct {
	RunID     string `dynamodbav:"run_id"`
	RepoKey   string `dynamodbav:"repo_key"`
	CommandID string `dynamodbav:"command_id"`
	// Status is the command's: CommandSucceeded or CommandFailed.
	Status string `dynamodbav:"status"`
	Error  string `dynamodbav:"error,omitempty"`
	// EnvKey is the key its values were resealed onto: a pull request
	// leaves them out once it is revoked.
	EnvKey string            `dynamodbav:"env_key,omitempty"`
	Items  []ResealBatchItem `dynamodbav:"items,omitempty"`
}

// ResealBatchItem is what a command did with one value: a reseal.v1
// result's item, with the document it is for.
type ResealBatchItem struct {
	ID         string `dynamodbav:"id"`
	Namespace  string `dynamodbav:"namespace"`
	Name       string `dynamodbav:"name"`
	Scope      string `dynamodbav:"scope"`
	Status     string `dynamodbav:"status"`
	Ciphertext string `dynamodbav:"ciphertext,omitempty"`
	From       string `dynamodbav:"from,omitempty"`
	Error      string `dynamodbav:"error,omitempty"`
}

// resealWorkRetention keeps a run's work and command results this long:
// longer than any run lasts, and they are of no use once it is done.
const resealWorkRetention = 30 * 24 * time.Hour

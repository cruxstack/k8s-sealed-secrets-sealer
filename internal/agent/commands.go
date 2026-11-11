package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// Command polling.
const (
	// pollWait is how long the control plane may hold a commands poll.
	pollWait = 20 * time.Second
	// pollRetry is the pause after a failed poll; it doubles with each
	// failure in a row, up to pollRetryMax.
	pollRetry    = 5 * time.Second
	pollRetryMax = time.Minute
	// pollMinInterval paces polls that come back empty at once, which a
	// control plane holding the poll never does.
	pollMinInterval = 2 * time.Second
	// maxErrorLen bounds the error reported for a failed command.
	maxErrorLen = 1024
	// ShutdownGrace is how long the runner keeps working once told to stop.
	// A poll in flight may still lease commands, which are gone from the
	// queue once leased, so they are run and reported rather than dropped.
	// It covers a held poll and a few commands.
	ShutdownGrace = 45 * time.Second
	// shutdownReport is how long, after the grace period, the runner takes
	// to report the commands it did not finish as failed, so the control
	// plane need not wait for them to expire. The chart's
	// terminationGracePeriodSeconds (60) leaves room for both.
	shutdownReport = 10 * time.Second
	// resultRetry is the pause after a failed attempt to report a result; it
	// doubles up to resultRetryMax.
	resultRetry    = time.Second
	resultRetryMax = 10 * time.Second
)

// CommandClient is the part of the control plane API commands use.
type CommandClient interface {
	Commands(ctx context.Context, wait time.Duration) ([]protocol.Command, error)
	Result(ctx context.Context, id string, res protocol.CommandResult) error
}

// HandlerFunc runs one command. It returns the result to report; a non-nil
// error fails the command, with the result still reported.
type HandlerFunc func(ctx context.Context, cmd protocol.Command) (any, error)

// Commands leases commands from the control plane and runs them, one at a
// time. Only command types with a handler are run; each handler is
// registered only when the agent has the command's capability.
type Commands struct {
	client   CommandClient
	handlers map[string]HandlerFunc
	logger   *slog.Logger
	now      func() time.Time
	// grace, shutdownReport and resultRetry are the constants, overridden in
	// tests
	grace          time.Duration
	shutdownReport time.Duration
	resultRetry    time.Duration
}

// NewCommands returns a command runner. It makes no network calls. now is
// the control plane's time, which commands expire in.
func NewCommands(client CommandClient, logger *slog.Logger, now func() time.Time) *Commands {
	if logger == nil {
		logger = slog.Default()
	}
	if now == nil {
		now = time.Now
	}
	return &Commands{
		client: client, handlers: map[string]HandlerFunc{}, logger: logger, now: now,
		grace: ShutdownGrace, shutdownReport: shutdownReport, resultRetry: resultRetry,
	}
}

// Handle registers the handler for a command type.
func (c *Commands) Handle(commandType string, h HandlerFunc) {
	c.handlers[commandType] = h
}

// Types returns the command types this agent runs, for its check-in.
func (c *Commands) Types() []string {
	out := make([]string, 0, len(c.handlers))
	for t := range c.handlers {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Run polls for commands until ctx ends. It does nothing when no command
// type has a handler. When ctx ends it starts no new poll, but the poll in
// flight and the commands it leased still run and are reported, for up to
// the shutdown grace period. Those still unfinished then are reported as
// failed.
func (c *Commands) Run(ctx context.Context) error {
	if len(c.handlers) == 0 {
		<-ctx.Done()
		return nil
	}
	work, report, cancel := c.workContext(ctx)
	defer cancel()
	retry := pollRetry
	for ctx.Err() == nil {
		retry = c.poll(ctx, work, report, retry)
	}
	return nil
}

// workContext returns the contexts polls and commands run in (work) and
// results are reported in (report). work ends the grace period after stop
// does, and report shutdownReport after that, so the commands cut off at
// the end of the grace period are still reported.
func (c *Commands) workContext(stop context.Context) (work, report context.Context, cancel context.CancelFunc) {
	work, cancelWork := context.WithCancel(context.WithoutCancel(stop))
	report, cancelReport := context.WithCancel(context.WithoutCancel(stop))
	unregister := context.AfterFunc(stop, func() {
		time.AfterFunc(c.grace, cancelWork)
		time.AfterFunc(c.grace+c.shutdownReport, cancelReport)
	})
	return work, report, func() {
		unregister()
		cancelWork()
		cancelReport()
	}
}

// poll leases and runs one batch of commands. A failed poll is logged and
// followed by a pause that grows with each failure in a row; it returns the
// next pause.
func (c *Commands) poll(stop, work, report context.Context, retry time.Duration) time.Duration {
	started := time.Now()
	cmds, err := c.client.Commands(work, pollWait)
	if err != nil {
		if stop.Err() != nil {
			// shutting down
			return retry
		}
		c.logger.WarnContext(work, "failed to poll for commands",
			"event", "agent.poll_failed", "error", err, "retry_in", retry.String())
		sleep(stop, retry)
		return min(2*retry, pollRetryMax)
	}
	for _, cmd := range cmds {
		c.execute(work, report, cmd)
	}
	if len(cmds) == 0 {
		sleep(stop, pollMinInterval-time.Since(started))
	}
	return pollRetry
}

// execute runs one leased command in ctx and reports its result in
// report. It re-validates what it can: the type is one it handles and the
// command has not expired. Once ctx has ended, at the end of the shutdown
// grace period, it runs nothing and reports the command as failed.
func (c *Commands) execute(ctx, report context.Context, cmd protocol.Command) {
	log := c.logger.With("command_id", cmd.ID, "type", cmd.Type)
	remaining := cmd.ExpiresAt.Sub(c.now())
	if remaining <= 0 {
		// not reported: the control plane accepts no result after expiry
		log.WarnContext(ctx, "command expired before it could run", "event", "command.expired", "expires_at", cmd.ExpiresAt)
		return
	}
	res := protocol.CommandResult{Status: protocol.CommandSucceeded}
	h, ok := c.handlers[cmd.Type]
	switch {
	case ctx.Err() != nil:
		res = protocol.CommandResult{Status: protocol.CommandFailed, Error: errShutDown}
	case !ok:
		res = protocol.CommandResult{Status: protocol.CommandFailed, Error: "unsupported command type"}
	default:
		runCtx, cancel := context.WithTimeout(ctx, remaining)
		log.InfoContext(ctx, "running command", "event", "command.started")
		out, err := c.run(runCtx, log, h, cmd)
		cancel()
		if out != nil {
			if b, mErr := json.Marshal(out); mErr == nil {
				res.Result = b
			}
		}
		if err != nil {
			msg := err.Error()
			if ctx.Err() != nil {
				msg = errShutDown + ": " + msg
			}
			res.Status, res.Error = protocol.CommandFailed, truncate(msg, maxErrorLen)
		}
	}
	if res.Status == protocol.CommandFailed {
		log.WarnContext(report, "command failed", "event", "command.failed", "error", res.Error)
	} else {
		log.InfoContext(report, "command succeeded", "event", "command.succeeded")
	}
	c.report(report, log, cmd, res)
}

// errShutDown is the error of a command the agent did not finish before it
// stopped, or did not run.
const errShutDown = "the agent shut down before the command finished"

// run calls a handler. A panic fails the command instead of stopping the
// agent.
func (c *Commands) run(ctx context.Context, log *slog.Logger, h HandlerFunc, cmd protocol.Command) (out any, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.ErrorContext(ctx, "command handler panicked",
				"event", "command.panicked", "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			out, err = nil, errors.New("the agent failed while running the command")
		}
	}()
	return h(ctx, cmd)
}

// report sends a command's result, retrying while the control plane cannot
// be reached or is failing, until the command expires: the control plane
// accepts results only until then.
func (c *Commands) report(ctx context.Context, log *slog.Logger, cmd protocol.Command, res protocol.CommandResult) {
	if !c.now().Before(cmd.ExpiresAt) {
		log.WarnContext(ctx, "command expired before its result could be reported",
			"event", "command.expired", "expires_at", cmd.ExpiresAt)
		return
	}
	pause := c.resultRetry
	for {
		err := c.client.Result(ctx, cmd.ID, res)
		if err == nil {
			return
		}
		if !retryable(err) || ctx.Err() != nil || !c.now().Add(pause).Before(cmd.ExpiresAt) {
			log.WarnContext(ctx, "failed to report command result", "event", "command.report_failed", "error", err)
			return
		}
		sleep(ctx, pause)
		pause = min(2*pause, resultRetryMax)
	}
}

// sleep waits d, or until ctx ends.
func sleep(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// truncate cuts s to at most n bytes, at a rune boundary, so the result is
// valid UTF-8 that stays within n once encoded.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

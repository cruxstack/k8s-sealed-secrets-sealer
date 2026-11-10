package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// Command polling.
const (
	// pollWait is how long the control plane may hold a commands poll.
	pollWait = 20 * time.Second
	// pollRetry is the pause after a failed poll.
	pollRetry = 5 * time.Second
	// maxErrorLen bounds the error reported for a failed command.
	maxErrorLen = 1024
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
}

// NewCommands returns a command runner. It makes no network calls.
func NewCommands(client CommandClient, logger *slog.Logger, now func() time.Time) *Commands {
	if logger == nil {
		logger = slog.Default()
	}
	if now == nil {
		now = time.Now
	}
	return &Commands{client: client, handlers: map[string]HandlerFunc{}, logger: logger, now: now}
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
// type has a handler.
func (c *Commands) Run(ctx context.Context) error {
	if len(c.handlers) == 0 {
		<-ctx.Done()
		return nil
	}
	for ctx.Err() == nil {
		c.poll(ctx)
	}
	return nil
}

// poll leases and runs one batch of commands. A failed poll is logged and
// followed by a pause.
func (c *Commands) poll(ctx context.Context) {
	cmds, err := c.client.Commands(ctx, pollWait)
	if err != nil {
		if ctx.Err() != nil {
			// shutting down
			return
		}
		c.logger.WarnContext(ctx, "failed to poll for commands",
			"event", "agent.poll_failed", "error", err)
		select {
		case <-ctx.Done():
		case <-time.After(pollRetry):
		}
		return
	}
	for _, cmd := range cmds {
		c.execute(ctx, cmd)
	}
}

// execute runs one leased command and reports its result. It re-validates
// what it can: the type is one it handles and the command has not expired.
func (c *Commands) execute(ctx context.Context, cmd protocol.Command) {
	log := c.logger.With("command_id", cmd.ID, "type", cmd.Type)
	if !c.now().Before(cmd.ExpiresAt) {
		log.WarnContext(ctx, "dropping expired command", "event", "command.expired", "expires_at", cmd.ExpiresAt)
		return
	}
	res := protocol.CommandResult{Status: protocol.CommandSucceeded}
	h, ok := c.handlers[cmd.Type]
	if !ok {
		res = protocol.CommandResult{Status: protocol.CommandFailed, Error: "unsupported command type"}
	} else {
		runCtx, cancel := context.WithDeadline(ctx, cmd.ExpiresAt)
		log.InfoContext(ctx, "running command", "event", "command.started")
		out, err := h(runCtx, cmd)
		cancel()
		if out != nil {
			if b, mErr := json.Marshal(out); mErr == nil {
				res.Result = b
			}
		}
		if err != nil {
			res.Status = protocol.CommandFailed
			res.Error = truncate(err.Error(), maxErrorLen)
		}
	}
	if res.Status == protocol.CommandFailed {
		log.WarnContext(ctx, "command failed", "event", "command.failed", "error", res.Error)
	} else {
		log.InfoContext(ctx, "command succeeded", "event", "command.succeeded")
	}
	if err := c.client.Result(ctx, cmd.ID, res); err != nil {
		log.WarnContext(ctx, "failed to report command result", "event", "command.report_failed", "error", err)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

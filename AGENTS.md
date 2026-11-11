# Agent Guidelines

## Architecture Overview
- **What it is**: one web app, for one environment or several on one URL, for sealing Kubernetes secrets with [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets), backed by an agent in every cluster. Users never pick a cluster or region. The full design is in `docs/design.md`; read it before changing behavior.
- **Control plane**: serves the UI and API, talks to GitHub, queues commands for agents, stores state in DynamoDB. Runs on AWS Lambda behind API Gateway (preferred) or as a container. It has no Kubernetes client and must never get one.
- **Agent**: runs beside a sealed-secrets controller, makes only outbound calls, reports the controller's keys, seals values and syncs keys. What it may do is set by its Helm values (capabilities), never by the control plane.
- **Entry points**:
  - `cmd/server/` - control plane as an HTTP server (containers, local stack)
  - `cmd/agent/` - the agent
  - `cmd/lambda/` - control plane on Lambda: API Gateway HTTP API (payload 2.0) and function URL events to the same HTTP handler, and `{"sealer": "tick"}` events from a schedule to ticks
  - `internal/app/` - wires the control plane together from its configuration, for `cmd/server` and `cmd/lambda` alike, with the ticker that advances reseal schedules and runs in a container; with the GitHub App's credentials in an SSM parameter that does not exist yet, starts in setup mode and switches to the App once the setup page creates it
- **Packages**:
  - `internal/config/` - reads and validates all configuration; nothing else reads the environment
  - `internal/protocol/` - the agent API's messages and capabilities; a change here is a protocol change
  - `internal/controlplane/` - the control plane's HTTP handler (agent API, admin API, user API), shared by the server and Lambda entry points; key sync planning (escrow, restore, renewal) runs on each check-in; sessions, seal requests (transit encryption, agent choice) and seal results becoming pending changes; resealing: a file in a session, schedules and their runs driven by ticks (`Server.Tick`), and reseal pull requests
  - `internal/agentauth/` - agent login (k8s-oidc: projected service-account tokens via go-oidc; aws-sts: signed sts:GetCallerIdentity forwarded to STS, with a host allowlist and replay protection) and agent session tokens
  - `internal/registry/` - the agent registry file: who may log in, with which identity and capabilities
  - `internal/fleet/` - pure computation of agent health, the env key, missing keys and which agent seals (design section 7)
  - `internal/store/` - persistence: DynamoDB, plus an in-memory store for tests
  - `internal/keys/` - sealing key fingerprints (the controller's own format) from certificates
  - `internal/envelope/` - KMS envelope encryption (data key + AES-256-GCM, bound to an encryption context), with a fake KMS for tests
  - `internal/agent/` - controller access (cert via the API service proxy, key Secrets, Deployment flags), login identities (projected token or signed STS request), the control plane client, the agent loop and probes, the command runner, sealing (seal.v1), resealing (reseal.v1: rewrapping a value's one-time key for the env key), key escrow and restore, and turning on key renewal
  - `internal/httpserver/` - HTTP server with timeouts and graceful shutdown, JSON responses
  - `internal/testutil/testcerts/` - throwaway keys and certificates for tests
  - `internal/version/` - build version, set at link time
  - `internal/userauth/` - GitHub OAuth sign-in (org and team checks), user session cookies, CSRF
  - `internal/githubsetup/` - the GitHub App setup page's API: GitHub's manifest flow (state cookie, owner check), and the App's credentials in an SSM SecureString parameter written once
  - `internal/githubapp/` - the GitHub App client: App JWTs, least-privilege installation tokens, repository reads, and pull requests (one commit on a new branch)
  - `internal/manifest/` - finds an env's SealedSecret documents in a YAML file (scope, keys, why one cannot be sealed into), and edits only their `spec.encryptedData` in place, byte for byte elsewhere
  - `internal/repos/` - repository access for signed-in users, checked against their own GitHub permission; SealedSecret discovery at the head or at a session's commit; pull requests of sealed values
  - `internal/webui/` - serves the web UI embedded from `internal/webui/dist/app` (built by `atmos web build`)
  - `internal/mockgithub/`, `cmd/mock-github/` - GitHub mock (OAuth, GitHub Apps, including ones created from a manifest, fixture repositories in `internal/mockgithub/fixtures`, Git writes and pull requests with a page per pull request) for tests and the local stack; never released
  - `internal/mockssm/`, `cmd/mock-ssm/` - SSM Parameter Store mock (GetParameter, PutParameter) holding the local stack's GitHub App credentials; never released
- **Web UI**: `web/` (React, Vite, TanStack Router and Query, shadcn/ui). `atmos web check|test|build|dev`.
- **Deploy**: `deploy/helm/agent` and `deploy/helm/control-plane`. AWS infrastructure lives in the separate `terraform-aws-k8s-sealed-secrets-sealer` repository.

## Build & Test
Atmos is the task runner; every command installs its pinned tools into `.tools/` on first use. Run `atmos list commands` to see them all.
- **Unit tests**: `atmos test unit` (race detector, plus the release and dev status scripts' tests; no network, cluster or Docker)
- **Integration tests**: `atmos test integration` (the DynamoDB store against DynamoDB Local, and envelope encryption against local KMS, both in Docker)
- **Single package or test**: `atmos test unit -- -run TestParseCert ./internal/keys`
- **Static checks**: `atmos check all` (tidy, fmt, lint, govulncheck, Helm charts); `atmos check fmt --write` formats
- **End-to-end**: `atmos test e2e` (throwaway k3d cluster `sealer-e2e`; `--keep` leaves it up)
- **Everything CI runs**: `atmos verify pr` (`--fast` skips e2e)
- **Binaries / images**: `atmos build bin`, `atmos build image <control-plane|agent>`

## Local Stack
- `atmos dev up` runs the whole system in the k3d cluster `sealer` with Tilt: control plane, DynamoDB Local, local KMS, and the simulated clusters in `dev/stack.yaml` (each with its own sealed-secrets controller and agent).
- Coding agents use the worktree-isolated commands instead, from a dedicated Git worktree: `atmos dev agent up`, `atmos dev agent status`, `atmos dev agent down`. Each worktree gets its own k3d cluster and ports.
- Use `atmos dev agent down` when the work is finished. Do not run `atmos dev agent destroy` or `atmos dev destroy` without an explicit request; they delete clusters and every sealing key in them.
- `atmos test e2e` is already isolated from the development stacks.

## UI pull requests

Follow [UI conventions](docs/ui-conventions.md) when adding or changing console
tables, toolbars, row details, and buttons.

Every pull request with UI changes must include screenshots embedded in the PR
description. Capture the affected screens from the local, worktree-isolated
stack created with `atmos dev agent`, using local mocks and anonymized data.
Capture desktop screenshots in the light theme at 1440×1100 by default; use a
taller viewport when needed for the specific screen. Do not capture narrow or
dark-theme layouts unless the PR specifically addresses dark-mode issues. Add
concise captions explaining what each screenshot demonstrates.

Commit screenshots under `docs/screenshots/<pr-number>/` and embed them with
commit-pinned, private-repository-safe GitHub URLs:

```md
![Description](https://github.com/cruxstack/k8s-sealed-secrets-sealer/blob/<commit-sha>/docs/screenshots/<pr-number>/<image>.png?raw=true)
```

Do not link directly to `raw.githubusercontent.com`. The `blob` URL lets GitHub
provide the authenticated, short-lived download token for private images.

## Code Style
- **Imports**: stdlib, blank line, third-party, blank line, local (`github.com/cruxstack/k8s-sealed-secrets-sealer/...`); `atmos check fmt --write` enforces it
- **Naming**: `PascalCase` exports, `camelCase` private
- **Constructors**: `New(Options)`; constructors make no network calls
- **Comments**: lowercase inline comments; doc comments are full sentences; explain why, not what
- **Logging**: `log/slog` with key-value pairs and snake_case keys, `*Context` methods where a context exists. Operational events carry an `event` key (e.g. `controller.key_active`) so they can be alerted on; `docs/design.md` lists the key sync alerts (section 8) and the events that make up the audit trail (section 11). A new event that records who did what belongs in that list.

## Configuration
- All variables are read in `internal/config`; nothing else reads the environment (dev-only tools such as `cmd/mock-github` excepted)
- Settings use the `APP_` prefix
- Validate at load time and report every problem at once; invalid configuration is an error, never a silent default

## Error Handling
- **Style**: lowercase, action-focused: `"failed to {action} {object}: {context}"`, with identifiers (namespace/name, fingerprint)
- **Wrapping**: `fmt.Errorf("...: %w", err)`, `errors.Is`, `errors.As`, `errors.Join`; don't log and return the same error
- The HTTP layer never returns error details to clients

## Security
- Never log, return or store plaintext secret values or private keys. Ciphertext is returned only where the design says so.
- The control plane never gets a Kubernetes client or a service account token (`automountServiceAccountToken: false`).
- Agent RBAC is namespaced to the controller's namespace. The one exception is the `cleanup` capability's `list` on SealedSecrets cluster-wide; with `keys` the agent holds its cluster's private keys, so that lets it decrypt every SealedSecret they sealed. Add nothing else cluster-wide. New permissions belong behind a capability that is off by default.
- Refuse `cluster-wide` sealing scope.
- Keep the project agnostic: no organization-specific names, domains, account IDs or topology in code, docs, tests or fixtures. Use neutral examples (envs `dev`/`prod`, regions `use1`/`use2`, clusters `blue`/`green`, `example.com`).

## Markdown Style
- **Line length**: Max 80 characters for prose text
- **Exceptions**: Code blocks, links, ASCII art, tables
- **Table alignment**: Align columns in plaintext for readability
- **Wrapping**: Break at natural boundaries (commas, periods, conjunctions)
- **Lists**: Indent continuation lines with 2 spaces

NOTE: AGENTS.md itself is exempt from the 80-character line limit.

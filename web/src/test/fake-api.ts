import { AxiosError, type AxiosAdapter } from "axios";
import type {
  FileListing,
  FileReseal,
  Fleet,
  FleetAgent,
  FleetKey,
  KeyClusterReferences,
  KeyReferences,
  KeyStatus,
  KeyUsage,
  MeResponse,
  PendingChange,
  Repository,
  ResealPullRequest,
  ResealRun,
  ResealRunSummary,
  ResealSchedule,
  ResealScheduleInput,
  Seal,
  SealSession,
  SealingStatus,
} from "@/api/types";

export const ME: MeResponse = {
  user: {
    id: 1,
    login: "octocat",
    name: "The Octocat",
    avatar_url: "https://avatars.githubusercontent.com/u/1",
  },
  envs: [{ name: "dev", admin: false }],
  csrf_token: "csrf-token-1",
};

/** ME, as an admin of dev: a member of its admin team, who sees its fleet. */
export const ADMIN: MeResponse = {
  ...ME,
  envs: [{ name: "dev", admin: true }],
};

/** ME, with dev and prod, administering only prod. */
export const TWO_ENVS: MeResponse = {
  ...ME,
  envs: [
    { name: "dev", admin: false },
    { name: "prod", admin: true },
  ],
};

export const STATUS: SealingStatus = {
  env: "dev",
  sealing: "ready",
  message: "Sealing works in all 2 clusters.",
  clusters: { ready: 2, total: 2 },
  can_reseal: true,
};

export interface Recorded {
  method: string;
  /** The path under /api/v1, without the env's /envs/{env} prefix. */
  url: string;
  /** The env the call was about; none for signing in. */
  env?: string;
  csrf: string | undefined;
  params?: Record<string, string>;
  /** The JSON body, parsed. */
  body?: unknown;
}

export interface FakeApi {
  adapter: AxiosAdapter;
  calls: Recorded[];
  /** The resealing state the routes serve and change; tests may change it. */
  reseal: {
    schedules: ResealSchedule[];
    runs: ResealRunSummary[];
    pullRequests: ResealPullRequest[];
  };
}

/**
 * A fake control plane for axios: `/auth/me` answers with `me` (or 401),
 * `/fleet` with `fleet` (403 unless `me` is an admin), `/status` with
 * `status`, `/auth/logout` with 204, and the repository and session routes
 * from their options; anything else is 404.
 */
export function fakeApi(opts: {
  me: MeResponse | null;
  fleet?: Fleet | null;
  fleetStatus?: number;
  status?: SealingStatus;
  repos?: Repository[];
  /** Marks the repository list as cut short by GitHub. */
  reposIncomplete?: boolean;
  /** File listings by "owner/repo"; others answer 404. */
  files?: Record<string, FileListing>;
  reposStatus?: number;
  /** Open sessions by "owner/repo"; changed by the session routes. */
  sessions?: Record<string, SealSession>;
  /** What a seal's progress answers, in order; the last one repeats. */
  sealStatuses?: Seal["status"][];
  sealError?: string;
  /** Answers a pull request with this error instead of opening one. */
  pullRequestError?: { status: number; error: string };
  /** Answers revoking, reinstating or deleting a key with this error. */
  keyStatusError?: { status: number; error: string };
  /** The env's resealing; changed by its routes. Only admins may see it. */
  reseal?: ResealFixtures;
  /** What a file reseal's progress answers, in order; the last repeats. */
  fileReseals?: FileReseal[];
  /** Answers "Reseal all" with this error instead of starting. */
  fileResealError?: { status: number; error: string };
  /** The pending changes a file reseal adds once it is done. */
  resealChanges?: PendingChange[];
  /**
   * Ends the session (as if it expired) once a file reseal's progress was
   * read this many times: later calls about it answer 404.
   */
  endSessionAfterResealPolls?: number;
}): FakeApi {
  const calls: Recorded[] = [];
  // copies, so the routes never change the caller's fixtures
  const sessions: Record<string, SealSession> = Object.fromEntries(
    Object.entries(opts.sessions ?? {}).map(([k, v]) => [
      k,
      { ...v, changes: [...(v.changes ?? [])] },
    ]),
  );
  let polls = 0;
  let resealPolls = 0;
  // as the control plane, a pull request waits for seals and reseals in
  // flight, and a reseal for seals
  let sealRunning = false;
  let resealRunning = false;
  const reseal = resealState(opts.reseal);
  const adapter: AxiosAdapter = async (config) => {
    // calls about an env come under /envs/{env}
    const scoped = /^\/envs\/([^/]+)(\/.*)$/.exec(config.url ?? "");
    const env = scoped ? decodeURIComponent(scoped[1]!) : undefined;
    const url = scoped ? scoped[2]! : (config.url ?? "");
    const method = (config.method ?? "get").toUpperCase();
    const body: unknown =
      typeof config.data === "string" ? JSON.parse(config.data) : undefined;
    calls.push({
      method,
      url,
      env,
      csrf: config.headers.get("X-CSRF-Token")?.toString(),
      params: config.params as Record<string, string> | undefined,
      body,
    });
    const reply = (status: number, payload: unknown) => {
      // a copy, as from the network: later changes to the fake's state must
      // not reach data the client already holds
      const data: unknown =
        typeof payload === "object" ? structuredClone(payload) : payload;
      const response = { data, status, statusText: "", headers: {}, config };
      if (status >= 400) {
        throw new AxiosError("error", "ERR_BAD_REQUEST", config, {}, response);
      }
      return response;
    };
    if (url === "/auth/me") {
      return opts.me
        ? reply(200, opts.me)
        : reply(401, { error: "unauthorized" });
    }
    if (url === "/fleet") {
      if (!opts.me) return reply(401, { error: "unauthorized" });
      if (!opts.me.envs.find((e) => e.name === env)?.admin) {
        return reply(403, { error: "only admins can see this" });
      }
      if (opts.fleetStatus)
        return reply(opts.fleetStatus, { error: "internal error" });
      return reply(200, opts.fleet ?? emptyFleet());
    }
    const keyStatus = /^\/keys\/([^/]+)\/(revoke|reinstate|delete)$/.exec(url);
    if (keyStatus && method === "POST") {
      if (!opts.me?.envs.find((e) => e.name === env)?.admin) {
        return reply(403, { error: "only admins can do this" });
      }
      if (opts.keyStatusError) {
        return reply(opts.keyStatusError.status, {
          error: opts.keyStatusError.error,
        });
      }
      const fingerprint = decodeURIComponent(keyStatus[1]!)
        .replace(/-/g, "+")
        .replace(/_/g, "/");
      const status = {
        revoke: "revoked",
        reinstate: "active",
        delete: "deleted",
      } as const;
      return reply(200, {
        fingerprint,
        status: status[keyStatus[2] as keyof typeof status],
        status_by: opts.me.user.login,
        status_at: new Date().toISOString(),
      } satisfies KeyStatus);
    }
    if (url.startsWith("/reseal/")) {
      if (!opts.me?.envs.find((e) => e.name === env)?.admin) {
        return reply(403, { error: "only admins can do this" });
      }
      const answer = resealRoute(
        reseal,
        method,
        url,
        config.params as Record<string, string> | undefined,
        body,
        opts.me.user.login,
      );
      return reply(answer.status, answer.body);
    }
    if (url === "/status") {
      if (!opts.me) return reply(401, { error: "unauthorized" });
      return reply(200, opts.status ?? STATUS);
    }
    if (url === "/auth/logout" && method === "POST") return reply(204, "");
    if (url === "/repos") {
      if (!opts.me) return reply(401, { error: "unauthorized" });
      if (opts.reposStatus)
        return reply(opts.reposStatus, { error: "GitHub request failed" });
      return reply(200, {
        repositories: opts.repos ?? [],
        incomplete: opts.reposIncomplete,
      });
    }
    if (url === "/sessions") {
      return reply(200, { sessions: Object.values(sessions) });
    }
    const session =
      /^\/repos\/([^/]+)\/([^/]+)\/session(?:\/([^/]+))?(\/.*)?$/.exec(url);
    if (session) {
      const [, owner = "", repo = "", id, rest = ""] = session;
      const key = `${decodeURIComponent(owner)}/${decodeURIComponent(repo)}`;
      const current = sessions[key];
      if (!id) {
        if (method === "GET") return reply(200, { session: current ?? null });
        const created: SealSession = current ?? {
          ...SESSION,
          repository: key,
          commit: (body as { commit: string }).commit,
          changes: [],
        };
        sessions[key] = created;
        return reply(current ? 200 : 201, { session: created });
      }
      if (!current || current.id !== id) {
        return reply(404, {
          error: "session not found; it may have expired or been discarded",
        });
      }
      if (method === "DELETE" && rest === "") {
        delete sessions[key];
        return reply(204, "");
      }
      if (method === "POST" && rest === "/seals") {
        polls = 0;
        sealRunning = true;
        return reply(202, {
          ...sealOf(body as SealRequest),
          status: "queued",
        });
      }
      const sealPoll = /^\/seals\/([^/]+)$/.exec(rest);
      if (method === "GET" && sealPoll) {
        const statuses = opts.sealStatuses ?? ["sealing", "sealed"];
        const status =
          statuses[Math.min(polls++, statuses.length - 1)] ?? "sealed";
        const last = calls.filter((c) => c.url.endsWith("/seals")).at(-1)
          ?.body as SealRequest;
        const seal: Seal = { ...sealOf(last), status };
        sealRunning = status === "queued" || status === "sealing";
        if (status === "sealed") {
          const change = changeFor(seal);
          current.changes = [
            ...(current.changes ?? []).filter((c) => c.id !== change.id),
            change,
          ];
          current.pending_changes = current.changes.length;
        }
        if (status === "failed" || status === "expired") {
          seal.error = opts.sealError ?? "the agent could not seal the value";
        }
        return reply(200, seal);
      }
      if (method === "POST" && rest === "/pull-request") {
        if (sealRunning || resealRunning) {
          return reply(409, {
            error:
              "a seal or reseal is still running; open the pull request once it finishes",
          });
        }
        if (opts.pullRequestError) {
          return reply(opts.pullRequestError.status, {
            error: opts.pullRequestError.error,
          });
        }
        const changes = current.changes ?? [];
        delete sessions[key];
        return reply(201, {
          pull_request: {
            number: 7,
            url: `https://github.com/${key}/pull/7`,
            branch: `sealer/dev/alice-${id.toLowerCase()}`,
            title: `Seal ${changes.length} values for dev`,
            files: new Set(changes.map((c) => c.path)).size,
            changes: changes.length,
          },
        });
      }
      if (method === "POST" && rest === "/reseals") {
        if (!opts.me?.envs.find((e) => e.name === env)?.admin) {
          return reply(403, { error: "only admins can do this" });
        }
        if (sealRunning) {
          return reply(409, {
            error:
              "a seal is still running in this session; reseal once it finishes",
          });
        }
        if (opts.fileResealError) {
          return reply(opts.fileResealError.status, {
            error: opts.fileResealError.error,
          });
        }
        resealPolls = 0;
        resealRunning = true;
        return reply(202, {
          ...fileReseal({ path: (body as { path: string }).path }),
          status: "queued",
        });
      }
      const resealPoll = /^\/reseals\/([^/]+)$/.exec(rest);
      if (method === "GET" && resealPoll) {
        if (resealPolls >= (opts.endSessionAfterResealPolls ?? Infinity)) {
          delete sessions[key];
          resealRunning = false;
          return reply(404, {
            error: "session not found; it may have expired or been discarded",
          });
        }
        const steps = opts.fileReseals ?? [fileReseal({ status: "done" })];
        const step = steps[Math.min(resealPolls++, steps.length - 1)]!;
        resealRunning = step.status === "queued" || step.status === "resealing";
        const path = (
          calls.filter((c) => c.url.endsWith("/reseals")).at(-1)?.body as {
            path: string;
          }
        ).path;
        if (step.status === "done") {
          const added = opts.resealChanges ?? [];
          current.changes = [
            ...(current.changes ?? []).filter(
              (c) => !added.some((a) => a.id === c.id),
            ),
            ...added,
          ];
          current.pending_changes = current.changes.length;
        }
        return reply(200, { ...step, path });
      }
      const change = /^\/changes\/([^/]+)$/.exec(rest);
      if (method === "DELETE" && change) {
        current.changes = (current.changes ?? []).filter(
          (c) => c.id !== change[1],
        );
        current.pending_changes = current.changes.length;
        return reply(204, "");
      }
      return reply(404, { error: "not found" });
    }
    const files = /^\/repos\/([^/]+)\/([^/]+)\/files$/.exec(url);
    if (files) {
      if (!opts.me) return reply(401, { error: "unauthorized" });
      const [, owner = "", repo = ""] = files;
      const listing =
        opts.files?.[
          `${decodeURIComponent(owner)}/${decodeURIComponent(repo)}`
        ];
      return listing
        ? reply(200, listing)
        : reply(404, { error: "repository not found" });
    }
    return reply(404, { error: "not found" });
  };
  return { adapter, calls, reseal };
}

export function emptyFleet(): Fleet {
  return {
    env: "dev",
    env_key: null,
    keys_in_sync: false,
    key_limit: 250,
    keys: [],
    agents: [],
  };
}

const NOW = Date.now();
const iso = (msAgo: number) => new Date(NOW - msAgo).toISOString();

export const KEY_A = {
  fingerprint: "SHA256:AAAAaaaaBBBBbbbbCCCCccccDDDDddddEEEEeeeeFFF",
  not_before: "2026-10-01T00:00:00Z",
  not_after: "2036-10-01T00:00:00Z",
};
export const KEY_B = {
  fingerprint: "SHA256:ZZZZzzzzYYYYyyyyXXXXxxxxWWWWwwwwVVVVvvvvUUU",
  not_before: "2026-11-01T00:00:00Z",
  not_after: "2036-11-01T00:00:00Z",
};

export function agent(
  overrides: Partial<FleetAgent> & { id: string },
): FleetAgent {
  return {
    cluster: "blue",
    region: "use1",
    registered_capabilities: ["seal", "keys"],
    checked_in: true,
    healthy: true,
    in_scope: true,
    last_checkin: iso(5_000),
    agent_version: "v0.1.0",
    capabilities: ["seal", "keys"],
    controller: {
      namespace: "sealed-secrets",
      name: "sealed-secrets-controller",
      key_renew_period: "720h0m0s",
      key_order_priority: "CertNotBefore",
      active_fingerprint: KEY_A.fingerprint,
    },
    keys: [KEY_A],
    keys_complete: true,
    keys_reported: 1,
    keys_dropped: 0,
    missing_keys: [],
    joining: false,
    issues: [],
    ...overrides,
  };
}

/** A key of the fleet, held by the given agents. */
export function fleetKey(
  key: typeof KEY_A,
  overrides: Partial<FleetKey> = {},
): FleetKey {
  return {
    ...key,
    holders: ["use1-blue"],
    escrow_copies: 1,
    env_key: false,
    status: "active",
    purged: false,
    future_dated: false,
    references: references([]),
    deletable: false,
    ...overrides,
  };
}

/** One cluster's count of a key's references, taken `msAgo`. */
export function counted(
  agent: string,
  values: number,
  sealedSecrets = values,
  msAgo = 60_000,
): KeyClusterReferences {
  return {
    agent,
    cluster: agent.replace(/^use\d-/, ""),
    values,
    sealed_secrets: sealedSecrets,
    counted_at: iso(msAgo),
  };
}

/**
 * A key's references: the clusters' counts, summed, and the agents whose
 * clusters did not count.
 */
export function references(
  clusters: KeyClusterReferences[],
  uncounted: string[] = [],
): KeyReferences {
  return {
    values: clusters.reduce((n, c) => n + c.values, 0),
    sealed_secrets: clusters.reduce((n, c) => n + c.sealed_secrets, 0),
    clusters,
    uncounted,
  };
}

/** An agent's latest count of the values in its cluster, a minute old. */
export function keyUsage(overrides: Partial<KeyUsage> = {}): KeyUsage {
  return {
    counted_at: iso(60_000),
    namespaces: null,
    sealed_secrets: 4,
    values: 12,
    unmatched: 0,
    ...overrides,
  };
}

/** An agent that counts references: `cleanup`, registered and reported. */
export const CLEANUP_CAPABILITIES = ["seal", "keys", "cleanup"];

export { iso };

export const REPO_APPS: Repository = {
  owner: "example-org",
  name: "apps",
  full_name: "example-org/apps",
  private: true,
  default_branch: "main",
  access: "write",
};

export const REPO_PLATFORM: Repository = {
  owner: "example-org",
  name: "platform",
  full_name: "example-org/platform",
  private: false,
  default_branch: "main",
  access: "read",
};

export function listing(overrides: Partial<FileListing> = {}): FileListing {
  return {
    repository: REPO_APPS,
    branch: "main",
    commit: "0123456789abcdef0123456789abcdef01234567",
    truncated: false,
    file_globs: ["*sealed*.yaml", "*sealed*.yml"],
    files: [
      {
        path: "deploy/billing/sealed-secret.yaml",
        blob: "1111111111111111111111111111111111111111",
        documents: [
          {
            index: 0,
            name: "billing",
            namespace: "dev-use1-blue-apps",
            regions: ["use1"],
            scope: "strict",
            keys: [],
          },
          {
            index: 2,
            name: "billing",
            namespace: "dev-use2-blue-apps",
            regions: ["use2"],
            scope: "strict",
            keys: ["api-key"],
          },
        ],
      },
      {
        path: "deploy/legacy/sealed-secret.yaml",
        blob: "2222222222222222222222222222222222222222",
        documents: [
          {
            index: 0,
            name: "legacy",
            namespace: "dev-use1-blue-apps",
            scope: "cluster-wide",
            keys: [],
            problem: "cluster-wide scope is not allowed",
          },
        ],
      },
      {
        path: "deploy/broken/sealed-secret.yaml",
        blob: "3333333333333333333333333333333333333333",
        documents: null,
        error: "file is not valid YAML",
      },
    ],
    ...overrides,
  };
}

export const SESSION: SealSession = {
  id: "01J00000000000000000000SES",
  repository: "example-org/apps",
  owner: "example-org",
  repo: "apps",
  branch: "main",
  commit: "0123456789abcdef0123456789abcdef01234567",
  created_at: iso(60_000),
  expires_at: new Date(NOW + 3_600_000).toISOString(),
  ends_at: new Date(NOW + 8 * 3_600_000).toISOString(),
  pending_changes: 0,
  changes: [],
};

export const SEAL: Seal = {
  id: "01J00000000000000000000SEA",
  status: "queued",
  path: "deploy/billing/sealed-secret.yaml",
  key: "api-token",
  targets: [
    {
      namespace: "dev-use1-blue-apps",
      name: "billing",
      scope: "strict",
      regions: ["use1"],
    },
    {
      namespace: "dev-use2-blue-apps",
      name: "billing",
      scope: "strict",
      regions: ["use2"],
    },
  ],
  agent: { id: "dev-use1-blue", cluster: "dev-use1-blue", region: "use1" },
  fingerprint: KEY_A.fingerprint,
  created_at: iso(1_000),
};

interface SealRequest {
  path: string;
  key: string;
  regions?: string[];
}

/** The seal the API answers a request with: its regions' documents. */
function sealOf({ path, key, regions }: SealRequest): Seal {
  return {
    ...SEAL,
    path,
    key,
    regions,
    targets: SEAL.targets.filter(
      (t) =>
        !regions ||
        ((t.regions ?? []).length > 0 &&
          (t.regions ?? []).every((r) => regions.includes(r))),
    ),
  };
}

export function changeFor(seal: Seal): PendingChange {
  return {
    id: ["change", seal.key, ...(seal.regions ?? [])].join("-"),
    path: seal.path,
    key: seal.key,
    regions: seal.regions,
    targets: seal.targets,
    sealed_at: iso(500),
    sealed_by: seal.agent,
    fingerprint: seal.fingerprint,
  };
}

// ---------------------------------------------------------------------------
// Resealing
// ---------------------------------------------------------------------------

/** The env's resealing, as the fake serves it. */
export interface ResealFixtures {
  schedules?: ResealSchedule[];
  /** Newest first. */
  runs?: ResealRunSummary[];
  /** A run's detail by ID; a run without one has no repositories. */
  details?: Record<string, ResealRun>;
  pullRequests?: ResealPullRequest[];
  /** Pull requests in repositories the viewer cannot read, per listing. */
  hidden?: number;
  /** Answers creating or changing a schedule with this error. */
  scheduleError?: { status: number; error: string };
  /** Answers Run now with this error. */
  runError?: { status: number; error: string };
}

interface ResealState {
  schedules: ResealSchedule[];
  runs: ResealRunSummary[];
  details: Record<string, ResealRun>;
  pullRequests: ResealPullRequest[];
  hidden: number;
  scheduleError?: { status: number; error: string };
  runError?: { status: number; error: string };
  created: number;
}

/** Copies, so the routes never change the caller's fixtures. */
function resealState(f: ResealFixtures = {}): ResealState {
  return {
    schedules: structuredClone(f.schedules ?? []),
    runs: structuredClone(f.runs ?? []),
    details: structuredClone(f.details ?? {}),
    pullRequests: structuredClone(f.pullRequests ?? []),
    hidden: f.hidden ?? 0,
    scheduleError: f.scheduleError,
    runError: f.runError,
    created: 0,
  };
}

const DAY = 86_400_000;

/** The reseal routes, as the control plane answers them. */
function resealRoute(
  state: ResealState,
  method: string,
  url: string,
  params: Record<string, string> | undefined,
  body: unknown,
  login: string,
): { status: number; body: unknown } {
  const ok = (b: unknown, status = 200) => ({ status, body: b });
  const fail = (status: number, error: string) => ({ status, body: { error } });
  if (url === "/reseal/schedules") {
    if (method === "GET") return ok({ schedules: state.schedules });
    if (state.scheduleError) {
      return fail(state.scheduleError.status, state.scheduleError.error);
    }
    const input = body as ResealScheduleInput;
    const created: ResealSchedule = {
      id: `sch-new-${++state.created}`,
      ...input,
      next_run_at: input.enabled
        ? new Date(Date.now() + input.interval_days * DAY).toISOString()
        : null,
      created_by: login,
      created_at: new Date().toISOString(),
    };
    state.schedules.push(created);
    return ok(created, 201);
  }
  const one = /^\/reseal\/schedules\/([^/]+)(\/run)?$/.exec(url);
  if (one) {
    const id = decodeURIComponent(one[1]!);
    const at = state.schedules.findIndex((s) => s.id === id);
    const schedule = state.schedules[at];
    if (!schedule) return fail(404, "schedule not found");
    if (one[2] && method === "POST") {
      if (state.runError) {
        return fail(state.runError.status, state.runError.error);
      }
      if (schedule.active_run_id) {
        return fail(409, "a run of this schedule is already in progress");
      }
      const started: ResealRunSummary = resealRun({
        id: `run-new-${++state.created}`,
        schedule_id: id,
        schedule_name: schedule.name,
        trigger: "manual",
        requested_by: login,
        status: "queued",
        repos: { total: 0, done: 0, hidden: 0 },
      });
      state.runs.unshift(started);
      schedule.active_run_id = started.id;
      schedule.last_run = started;
      return ok(started, 202);
    }
    if (method === "DELETE") {
      // as the control plane, deleting a schedule cancels its active run
      const active = state.runs.find((r) => r.id === schedule.active_run_id);
      if (active) {
        active.status = "cancelled";
        active.finished_at = new Date().toISOString();
      }
      state.schedules.splice(at, 1);
      return { status: 204, body: "" };
    }
    if (method === "PATCH") {
      if (state.scheduleError) {
        return fail(state.scheduleError.status, state.scheduleError.error);
      }
      const patch = body as Partial<ResealScheduleInput>;
      const next = { ...schedule, ...patch, updated_by: login };
      if (patch.enabled === false) next.next_run_at = null;
      if (patch.enabled === true && !schedule.enabled) {
        next.next_run_at = new Date(
          Date.now() + next.interval_days * DAY,
        ).toISOString();
      }
      state.schedules[at] = next;
      return ok(next);
    }
  }
  if (url === "/reseal/runs" && method === "GET") {
    const runs = state.runs.filter(
      (r) => !params?.schedule || r.schedule_id === params.schedule,
    );
    return ok({ runs: runs.slice(0, Number(params?.limit ?? 50)) });
  }
  const run = /^\/reseal\/runs\/([^/]+)(\/cancel)?$/.exec(url);
  if (run) {
    const id = decodeURIComponent(run[1]!);
    const summary = state.runs.find((r) => r.id === id);
    if (!summary) return fail(404, "run not found");
    if (run[2] && method === "POST") {
      if (summary.status !== "queued" && summary.status !== "running") {
        return fail(409, "the run has finished");
      }
      summary.status = "cancelled";
      summary.finished_at = new Date().toISOString();
      for (const s of state.schedules) {
        if (s.active_run_id === id) delete s.active_run_id;
      }
      return ok(summary);
    }
    if (method === "GET") {
      return ok(state.details[id] ?? { ...summary, repositories: [] });
    }
  }
  if (url === "/reseal/pull-requests" && method === "GET") {
    const filter = params?.state ?? "open";
    return ok({
      pull_requests: state.pullRequests.filter(
        (pr) => filter === "all" || pr.state === filter,
      ),
      hidden: state.hidden,
    });
  }
  return fail(404, "not found");
}

/** A schedule of example-org/apps every 75 days, created by alice. */
export function resealSchedule(
  overrides: Partial<ResealSchedule> & { id: string },
): ResealSchedule {
  return {
    name: "Apps",
    repos: ["example-org/apps"],
    orgs: [],
    interval_days: 75,
    enabled: true,
    // an hour past 40 days, so it reads "in 40d" however long tests take
    next_run_at: new Date(NOW + 40 * DAY + 3_600_000).toISOString(),
    created_by: "alice",
    created_at: iso(35 * DAY),
    ...overrides,
  };
}

/** A run of the Apps schedule that succeeded an hour ago. */
export function resealRun(
  overrides: Partial<ResealRunSummary> & { id: string },
): ResealRunSummary {
  return {
    schedule_id: "sch-apps",
    schedule_name: "Apps",
    trigger: "schedule",
    requested_by: "alice",
    status: "succeeded",
    started_at: iso(3_600_000),
    finished_at: iso(3_600_000 - 252_000),
    repos: { total: 2, done: 2, hidden: 0 },
    values: { resealed: 3, current: 10, failed: 0 },
    pull_requests: 1,
    ...overrides,
  };
}

/** An open reseal pull request a run of Apps opened two days ago. */
export function resealPullRequest(
  overrides: Partial<ResealPullRequest> & { number: number },
): ResealPullRequest {
  const repo = overrides.repo ?? "example-org/apps";
  return {
    repo,
    url: `https://github.com/${repo}/pull/${overrides.number}`,
    title: "Reseal 3 values in 2 files for dev",
    branch: "sealer/dev/reseal-run-1",
    state: "open",
    source: "schedule",
    schedule_id: "sch-apps",
    schedule_name: "Apps",
    run_id: "run-1",
    requested_by: "alice",
    opened_at: iso(2 * DAY),
    checked_at: iso(5 * 60_000),
    values: 3,
    files: 2,
    from_keys: [KEY_A.fingerprint],
    ...overrides,
  };
}

/** A file reseal of the billing file, done: 1 resealed, 1 current. */
export function fileReseal(overrides: Partial<FileReseal> = {}): FileReseal {
  return {
    id: "01J00000000000000000000RES",
    path: "deploy/billing/sealed-secret.yaml",
    status: "done",
    values: { total: 2, resealed: 1, current: 1, failed: 0, pending: 0 },
    agent: { id: "dev-use1-blue", cluster: "dev-use1-blue", region: "use1" },
    created_at: iso(1_000),
    ...overrides,
  };
}

import { AxiosError, type AxiosAdapter } from "axios";
import type {
  FileListing,
  Fleet,
  FleetAgent,
  MeResponse,
  PendingChange,
  Repository,
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
    if (url === "/status") {
      if (!opts.me) return reply(401, { error: "unauthorized" });
      return reply(200, opts.status ?? STATUS);
    }
    if (url === "/auth/logout" && method === "POST") return reply(204, "");
    if (url === "/repos") {
      if (!opts.me) return reply(401, { error: "unauthorized" });
      if (opts.reposStatus)
        return reply(opts.reposStatus, { error: "GitHub request failed" });
      return reply(200, { repositories: opts.repos ?? [] });
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
        return reply(404, { error: "session not found" });
      }
      if (method === "DELETE" && rest === "") {
        delete sessions[key];
        return reply(204, "");
      }
      if (method === "POST" && rest === "/seals") {
        polls = 0;
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
  return { adapter, calls };
}

export function emptyFleet(): Fleet {
  return { env: "dev", env_key: null, keys_in_sync: false, agents: [] };
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
    missing_keys: [],
    issues: [],
    ...overrides,
  };
}

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
            region: "use1",
            scope: "strict",
            keys: [],
          },
          {
            index: 2,
            name: "billing",
            namespace: "dev-use2-blue-apps",
            region: "use2",
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
      region: "use1",
    },
    {
      namespace: "dev-use2-blue-apps",
      name: "billing",
      scope: "strict",
      region: "use2",
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
      (t) => !regions || regions.includes(t.region ?? ""),
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

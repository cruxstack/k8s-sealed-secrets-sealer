import { AxiosError, type AxiosAdapter } from "axios";
import type { Fleet, FleetAgent, MeResponse } from "@/api/types";

export const ME: MeResponse = {
  user: {
    id: 1,
    login: "octocat",
    name: "The Octocat",
    avatar_url: "https://avatars.githubusercontent.com/u/1",
  },
  csrf_token: "csrf-token-1",
  env: "dev",
};

export interface Recorded {
  method: string;
  url: string;
  csrf: string | undefined;
}

export interface FakeApi {
  adapter: AxiosAdapter;
  calls: Recorded[];
}

/**
 * A fake control plane for axios: `/auth/me` answers with `me` (or 401),
 * `/fleet` with `fleet`, `/auth/logout` with 204; anything else is 404.
 */
export function fakeApi(opts: {
  me: MeResponse | null;
  fleet?: Fleet | null;
  fleetStatus?: number;
}): FakeApi {
  const calls: Recorded[] = [];
  const adapter: AxiosAdapter = async (config) => {
    const url = config.url ?? "";
    const method = (config.method ?? "get").toUpperCase();
    calls.push({
      method,
      url,
      csrf: config.headers.get("X-CSRF-Token")?.toString(),
    });
    const reply = (status: number, data: unknown) => {
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
      if (opts.fleetStatus)
        return reply(opts.fleetStatus, { error: "internal error" });
      return reply(200, opts.fleet ?? emptyFleet());
    }
    if (url === "/auth/logout" && method === "POST") return reply(204, "");
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

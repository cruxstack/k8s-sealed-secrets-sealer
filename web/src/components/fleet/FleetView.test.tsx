import { describe, it, expect, afterEach } from "vitest";
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import apiClient, { setApiEnv, setCsrfToken } from "@/api/client";
import type { Fleet } from "@/api/types";
import { FleetView } from "./FleetView";
import {
  ADMIN,
  KEY_A,
  KEY_B,
  agent,
  fakeApi,
  fleetKey,
  type FakeApi,
} from "@/test/fake-api";

function renderFleet(
  fleet: Fleet | null,
  fleetStatus?: number,
  opts: Partial<Parameters<typeof fakeApi>[0]> = {},
): FakeApi {
  setApiEnv("dev");
  setCsrfToken(ADMIN.csrf_token);
  const api = fakeApi({ me: ADMIN, fleet, fleetStatus, ...opts });
  apiClient.defaults.adapter = api.adapter;
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <FleetView />
    </QueryClientProvider>,
  );
  return api;
}

/** A key whose fingerprint has the characters URLs carry differently. */
const KEY_C = {
  fingerprint: "SHA256:Cc+c/cCCddDDeeEEffFFggGGhhHHiiIIjjJJkkKKllL",
  not_before: "2026-09-01T00:00:00Z",
  not_after: "2036-09-01T00:00:00Z",
};

/** The fleet with two agents holding KEY_A (the env key) and KEY_B. */
function keyedFleet(overrides: Partial<Fleet> = {}): Fleet {
  return {
    env: "dev",
    env_key: KEY_B,
    keys_in_sync: true,
    key_limit: 250,
    keys: [
      fleetKey(KEY_B, {
        holders: ["use1-blue", "use2-blue"],
        env_key: true,
        escrow_copies: 2,
      }),
      fleetKey(KEY_A, { holders: ["use1-blue", "use2-blue"] }),
      fleetKey(KEY_C, {
        holders: [],
        status: "revoked",
        revoked_by: "alice",
        revoked_at: new Date(Date.now() - 2 * 3_600_000).toISOString(),
      }),
    ],
    agents: [
      agent({ id: "use1-blue", keys: [KEY_A, KEY_B], keys_reported: 2 }),
      agent({
        id: "use2-blue",
        region: "use2",
        keys: [KEY_A, KEY_B],
        keys_reported: 2,
      }),
    ],
    ...overrides,
  };
}

/** A key's row in the keys table; its header is the short fingerprint. */
function keyRow(fingerprint: string) {
  const table = screen.getByRole("table", { name: /sealing keys/i });
  return within(table).getByTitle(fingerprint).closest("tr") as HTMLElement;
}

/** An agent's row; its header names the agent, then its cluster. */
function row(name: string) {
  return screen
    .getByRole("rowheader", { name: new RegExp(`^${name}( |$)`) })
    .closest("tr") as HTMLElement;
}

describe("FleetView", () => {
  const originalAdapter = apiClient.defaults.adapter;
  afterEach(() => {
    apiClient.defaults.adapter = originalAdapter;
  });

  it("shows the env key when keys are in sync", async () => {
    renderFleet({
      env: "dev",
      env_key: KEY_A,
      keys_in_sync: true,
      key_limit: 250,
      keys: [],
      agents: [
        agent({ id: "use1-blue" }),
        agent({ id: "use2-blue", region: "use2" }),
      ],
    });

    const banner = await screen.findByRole("region", {
      name: /environment key/i,
    });
    expect(within(banner).getByText("dev")).toBeInTheDocument();
    const fp = within(banner).getByTitle(KEY_A.fingerprint);
    expect(fp).toHaveTextContent("SHA256:AAAAaaaaBBBB…");
    expect(
      within(banner).getByRole("button", { name: /copy env key fingerprint/i }),
    ).toBeInTheDocument();
    expect(screen.queryByText(/keys out of sync/i)).not.toBeInTheDocument();
    const agentTable = screen.getByRole("table", { name: /agents/i });
    expect(within(agentTable).getAllByRole("row")).toHaveLength(3); // header + 2 agents
    expect(screen.getByRole("heading", { name: "Fleet" })).toBeInTheDocument();
    expect(screen.getByText("2 of 2 healthy")).toBeInTheDocument();
    // the agents whose active key is the env key say so
    expect(within(row("use1-blue")).getByText("env key")).toBeInTheDocument();
    // the cluster shows under the agent when it is named differently
    expect(
      screen.getByRole("rowheader", { name: "use1-blue blue" }),
    ).toBeInTheDocument();
  });

  it("warns when keys are out of sync and shows missing keys per agent", async () => {
    renderFleet({
      env: "dev",
      env_key: null,
      keys_in_sync: false,
      key_limit: 250,
      keys: [],
      agents: [
        agent({
          id: "use1-blue",
          keys: [KEY_A],
          missing_keys: [KEY_B.fingerprint],
        }),
        agent({
          id: "use1-green",
          keys: [KEY_B],
          missing_keys: [KEY_A.fingerprint],
          controller: {
            namespace: "sealed-secrets",
            name: "sealed-secrets-controller",
            active_fingerprint: KEY_B.fingerprint,
          },
        }),
      ],
    });

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/keys out of sync/i);
    // without an env key, no agent is marked as holding it
    expect(screen.queryByText("env key")).not.toBeInTheDocument();
    expect(
      within(row("use1-blue")).getByTitle(KEY_B.fingerprint),
    ).toHaveTextContent("1");
  });

  it("marks agents that never checked in and unhealthy agents", async () => {
    renderFleet({
      env: "prod",
      env_key: KEY_A,
      keys_in_sync: true,
      key_limit: 250,
      keys: [],
      agents: [
        agent({ id: "use1-blue" }),
        agent({
          id: "use1-green",
          healthy: false,
          last_checkin: new Date(Date.now() - 10 * 60_000).toISOString(),
          issues: ["has not checked in recently"],
        }),
        agent({
          id: "use2-blue",
          region: "use2",
          checked_in: false,
          healthy: false,
          in_scope: false,
          last_checkin: undefined,
          agent_version: undefined,
          capabilities: undefined,
          controller: undefined,
          keys: undefined,
          keys_complete: false,
          missing_keys: undefined,
          issues: ["has never checked in"],
        }),
      ],
    });

    await screen.findByRole("region", { name: /environment key/i });
    expect(screen.getByText("1 of 3 healthy")).toHaveClass("text-warning");
    expect(within(row("use1-blue")).getByText("Healthy")).toBeInTheDocument();
    expect(
      within(row("use1-green")).getByText("Unhealthy"),
    ).toBeInTheDocument();
    expect(within(row("use1-green")).getByText("10m ago")).toBeInTheDocument();
    expect(
      within(row("use1-green")).getByText("has not checked in recently"),
    ).toBeInTheDocument();
    const never = row("use2-blue");
    expect(within(never).getByText("Never checked in")).toBeInTheDocument();
    expect(within(never).getByText("has never checked in")).toBeInTheDocument();
    // registered capabilities still show for an agent that never checked in
    expect(within(never).getByText("seal")).toBeInTheDocument();
  });

  it("flags agents that report only their active key", async () => {
    renderFleet({
      env: "dev",
      env_key: KEY_A,
      keys_in_sync: true,
      key_limit: 250,
      keys: [],
      agents: [agent({ id: "use1-blue", keys_complete: false })],
    });
    await screen.findByRole("region", { name: /environment key/i });
    expect(
      within(row("use1-blue")).getByText("(active only)"),
    ).toBeInTheDocument();
  });

  it("shows an empty state without agents", async () => {
    renderFleet({
      env: "dev",
      env_key: null,
      keys_in_sync: false,
      key_limit: 250,
      keys: [],
      agents: null,
    });
    expect(
      await screen.findByText(/no agents registered/i),
    ).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("lists the keys with their holders, escrow and status", async () => {
    renderFleet(keyedFleet());
    await screen.findByRole("heading", { name: "Keys" });
    expect(screen.getByText("3 keys, 1 revoked")).toBeInTheDocument();

    const env = keyRow(KEY_B.fingerprint);
    expect(within(env).getByText("Env key")).toBeInTheDocument();
    expect(within(env).getByText("2 of 2")).toBeInTheDocument();
    expect(within(env).getByText("2")).toHaveAttribute(
      "title",
      expect.stringMatching(/2 escrowed copies/),
    );
    expect(
      within(keyRow(KEY_A.fingerprint)).getByText("Active"),
    ).toBeInTheDocument();
    const revoked = keyRow(KEY_C.fingerprint);
    expect(within(revoked).getByText("Revoked")).toBeInTheDocument();
    expect(within(revoked).getByText("by alice 2h ago")).toBeInTheDocument();
    expect(
      within(revoked).getByRole("button", { name: /reinstate key/i }),
    ).toBeInTheDocument();
    expect(
      within(revoked).queryByRole("button", { name: /revoke key/i }),
    ).not.toBeInTheDocument();
  });

  it("flags future-dated keys and keys with no escrowed copy", async () => {
    const planted = {
      fingerprint: "SHA256:PPPPppppQQQQqqqqRRRRrrrrSSSSssssTTTTttttUUU",
      not_before: "2099-01-01T00:00:00Z",
      not_after: "2109-01-01T00:00:00Z",
    };
    renderFleet(
      keyedFleet({
        keys: [
          fleetKey(planted, { future_dated: true, escrow_copies: 0 }),
          fleetKey(KEY_B, { env_key: true }),
        ],
      }),
    );
    await screen.findByRole("heading", { name: "Keys" });
    const row = keyRow(planted.fingerprint);
    expect(within(row).getByText("Future-dated")).toBeInTheDocument();
    expect(within(row).getByText("0")).toHaveClass("text-warning");
  });

  it("revokes a key after a dialog that says what revoking does", async () => {
    const api = renderFleet(keyedFleet());
    await screen.findByRole("heading", { name: "Keys" });
    fireEvent.click(
      within(keyRow(KEY_B.fingerprint)).getByRole("button", {
        name: /revoke key/i,
      }),
    );
    const dialog = await screen.findByRole("dialog", {
      name: "Revoke this key?",
    });
    // what it does, and what it does not
    expect(dialog).toHaveTextContent(/it is the env key/i);
    expect(dialog).toHaveTextContent(
      /does not remove the key from any cluster/i,
    );
    expect(dialog).toHaveTextContent(/still decrypt values sealed with it/i);
    expect(dialog).toHaveTextContent(/rotate the values sealed with it/i);
    expect(dialog).toHaveTextContent(/you can reinstate it/i);
    // nothing is sent until it is confirmed
    expect(api.calls.filter((c) => c.method === "POST")).toHaveLength(0);

    fireEvent.click(within(dialog).getByRole("button", { name: "Revoke key" }));
    await waitFor(() =>
      expect(
        screen.queryByRole("dialog", { name: "Revoke this key?" }),
      ).not.toBeInTheDocument(),
    );
    const posts = api.calls.filter((c) => c.method === "POST");
    expect(posts).toEqual([
      expect.objectContaining({
        url: `/keys/${encodeURIComponent(KEY_B.fingerprint)}/revoke`,
        env: "dev",
        csrf: ADMIN.csrf_token,
      }),
    ]);
    // the fleet is read again
    await waitFor(() =>
      expect(api.calls.filter((c) => c.url === "/fleet")).toHaveLength(2),
    );
  });

  it("does not mention the env key for another key, and shows a refusal", async () => {
    renderFleet(keyedFleet(), undefined, {
      keyStatusError: { status: 403, error: "only admins can do this" },
    });
    await screen.findByRole("heading", { name: "Keys" });
    fireEvent.click(
      within(keyRow(KEY_A.fingerprint)).getByRole("button", {
        name: /revoke key/i,
      }),
    );
    const dialog = await screen.findByRole("dialog");
    expect(dialog).not.toHaveTextContent(/it is the env key/i);
    fireEvent.click(within(dialog).getByRole("button", { name: "Revoke key" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "Could not revoke the key: only admins can do this",
    );
  });

  it("reinstates a revoked key, with its fingerprint in the URL-safe alphabet", async () => {
    const api = renderFleet(keyedFleet());
    await screen.findByRole("heading", { name: "Keys" });
    fireEvent.click(
      within(keyRow(KEY_C.fingerprint)).getByRole("button", {
        name: /reinstate key/i,
      }),
    );
    await waitFor(() =>
      expect(api.calls.filter((c) => c.method === "POST")).toEqual([
        expect.objectContaining({
          url: "/keys/SHA256%3ACc-c_cCCddDDeeEEffFFggGGhhHHiiIIjjJJkkKKllL/reinstate",
          csrf: ADMIN.csrf_token,
        }),
      ]),
    );
  });

  it("marks joining clusters", async () => {
    renderFleet(
      keyedFleet({
        agents: [
          agent({ id: "use1-blue", keys: [KEY_A, KEY_B] }),
          agent({
            id: "use2-blue",
            region: "use2",
            keys: [KEY_C],
            missing_keys: [KEY_A.fingerprint, KEY_B.fingerprint],
            joining: true,
            joined_at: new Date(Date.now() - 4 * 60_000).toISOString(),
            issues: [
              "joined 4 minutes ago; left out of the env key for up to 30 minutes while it restores the env's keys",
            ],
          }),
        ],
      }),
    );
    await screen.findByRole("heading", { name: "Keys" });
    const joining = within(row("use2-blue")).getByText("Joining");
    expect(joining).toHaveAttribute(
      "title",
      expect.stringMatching(/^Joined 4m ago; left out of the env key/),
    );
    expect(
      within(row("use1-blue")).queryByText("Joining"),
    ).not.toBeInTheDocument();
  });

  it("warns as a cluster's keys near the limit, and past it", async () => {
    renderFleet(
      keyedFleet({
        agents: [
          agent({ id: "use1-blue", keys_reported: 210 }),
          agent({ id: "use2-blue", region: "use2", keys_reported: 130 }),
        ],
      }),
    );
    const notice = await screen.findByRole("status", { name: "Key limit" });
    expect(notice).toHaveTextContent(
      "blue (and 1 more) holds 210 keys, 84% of the 250 kept per cluster",
    );
    expect(within(row("use1-blue")).getByText("210")).toHaveClass(
      "text-warning",
    );
  });

  it("says when keys are left out over the limit", async () => {
    renderFleet(
      keyedFleet({
        agents: [
          agent({ id: "use1-blue", keys_reported: 262, keys_dropped: 12 }),
          agent({ id: "use2-blue", region: "use2", keys_reported: 20 }),
        ],
      }),
    );
    const notice = await screen.findByRole("alert", { name: "Key limit" });
    expect(notice).toHaveTextContent(
      "blue reports 262 keys, more than the 250 kept per cluster",
    );
    expect(notice).toHaveTextContent("The 12 oldest are left out of key sync");
    expect(
      within(row("use1-blue")).getByText("(12 left out)"),
    ).toBeInTheDocument();
  });

  it("shows a load error", async () => {
    renderFleet(null, 500);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /could not load the fleet: the server encountered an error/i,
    );
  });
});

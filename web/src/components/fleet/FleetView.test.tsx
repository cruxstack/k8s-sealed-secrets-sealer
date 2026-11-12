import { describe, it, expect, afterEach } from "vitest";
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "sonner";
import apiClient, { setApiEnv, setCsrfToken } from "@/api/client";
import type { Fleet, FleetAgent, FleetKey } from "@/api/types";
import { TooltipProvider } from "@/components/ui/tooltip";
import { FleetView } from "./FleetView";
import {
  ADMIN,
  CLEANUP_CAPABILITIES,
  KEY_A,
  KEY_B,
  agent,
  counted,
  fakeApi,
  fleetKey,
  iso,
  keyUsage,
  references,
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
  // the app shell provides tooltips and toasts
  render(
    <QueryClientProvider client={queryClient}>
      <TooltipProvider delayDuration={0}>
        <FleetView />
        <Toaster />
      </TooltipProvider>
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

/**
 * A key's row in the keys table or the deleted keys table; its header is
 * the short fingerprint.
 */
function keyRow(fingerprint: string) {
  const [cell] = screen
    .getAllByRole("table", { name: /sealing keys/i })
    .flatMap((t) => within(t).queryAllByTitle(fingerprint));
  if (!cell) throw new Error(`no key row for ${fingerprint}`);
  return cell.closest("tr") as HTMLElement;
}

/**
 * A key's actions, in their order on its row: "enabled", or why not (the
 * grayed-out button's description).
 */
function keyActions(fingerprint: string): Record<string, string> {
  const buttons = within(keyRow(fingerprint))
    .getAllByRole("button")
    .filter((b) => /^(Revoke|Delete|Reinstate) key /.test(b.ariaLabel ?? ""));
  return Object.fromEntries(
    buttons.map((b) => [
      (b.ariaLabel ?? "").split(" ")[0],
      b.getAttribute("aria-disabled") === "true"
        ? // the first description is the reason; a tooltip open adds more
          (document.getElementById(
            (b.getAttribute("aria-describedby") ?? "").split(" ")[0]!,
          )?.textContent ?? "no reason")
        : "enabled",
    ]),
  );
}

/** The text of the tooltip on screen, if one is. */
function tooltipShown() {
  return document.querySelector("[data-radix-popper-content-wrapper]")
    ?.textContent;
}

/** An agent's details, opened from its name. */
function details(name: string) {
  const button = within(row(name)).getByRole("button", { name });
  if (button.getAttribute("aria-expanded") !== "true") fireEvent.click(button);
  return screen.getByLabelText(`Details of ${name}`);
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
      name: "Env key",
    });
    expect(within(banner).getByText("dev")).toBeInTheDocument();
    expect(
      within(banner).getByRole("heading", { name: "Keys in Sync" }),
    ).toBeInTheDocument();
    // when it became valid, as a relative time with the date in its title
    const valid = banner.querySelector("time");
    expect(valid).toHaveAttribute("dateTime", KEY_A.not_before);
    expect(valid).toHaveTextContent(/ ago$|^in /);
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
    // one line a row: the agent and its region, and what does not fit in
    // its details, which its name opens
    expect(
      screen.getByRole("rowheader", { name: "use1-blue use1" }),
    ).toBeInTheDocument();
    expect(
      within(agentTable)
        .getAllByRole("columnheader")
        .map((h) => h.textContent),
    ).toEqual([
      "Agent",
      "Health",
      "Keys",
      "Missing",
      "Active Key",
      "Sealed Values",
    ]);
    const name = within(row("use1-blue")).getByRole("button", {
      name: "use1-blue",
    });
    expect(name).toHaveAttribute("aria-expanded", "false");
    const open = details("use1-blue");
    expect(name).toHaveAttribute("aria-expanded", "true");
    expect(name).toHaveAttribute("aria-controls", open.closest("tr")?.id);
    // the cluster when it is named differently, and the version
    expect(open).toHaveTextContent(/Cluster\s*blue/);
    expect(open).toHaveTextContent(/Version\s*v0\.1\.0/);
    expect((open.closest("tr") as HTMLElement).previousElementSibling).toBe(
      row("use1-blue"),
    );
    expect(open.closest("td")).toHaveAttribute("colspan", "6");
    expect(within(agentTable).getAllByRole("row")).toHaveLength(4);
    fireEvent.click(name);
    expect(screen.queryByLabelText("Details of use1-blue")).toBeNull();
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
    // sealing is unavailable: destructive, as in the header and workspace
    expect(within(alert).getByText("Sealing Unavailable")).toHaveClass(
      "text-destructive",
    );
    // it points at the column that says what each cluster lacks
    expect(alert).toHaveTextContent(/the missing column below/i);
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
          keys_complete: false,
          issues: [
            "has not checked in recently",
            "reports only its controller's active key (no keys capability)",
          ],
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

    await screen.findByRole("region", { name: "Env key" });
    expect(screen.getByText("1 of 3 healthy")).toHaveClass("text-warning");
    expect(within(row("use1-blue")).getByText("Healthy")).toBeInTheDocument();
    expect(
      within(row("use1-green")).getByText("Unhealthy"),
    ).toBeInTheDocument();
    expect(within(row("use1-green")).getByText("10m ago")).toBeInTheDocument();
    // the rows stay one line: the other issues are a count beside the
    // health, which opens them in the agent's details, without the one the
    // badge already says
    const count = within(row("use1-green")).getByRole("button", {
      name: "1 Issue",
    });
    expect(count).toHaveClass("text-warning");
    fireEvent.click(count);
    expect(count).toHaveAttribute("aria-expanded", "true");
    const issues = within(details("use1-green")).getByRole("list", {
      name: "Issues of use1-green",
    });
    expect(issues).toHaveTextContent(
      "Reports only its controller's active key (no keys capability).",
    );
    expect(issues).not.toHaveTextContent(/checked in/);
    expect(
      within(row("use1-blue")).queryByRole("button", { name: /issue/ }),
    ).not.toBeInTheDocument();
    const never = row("use2-blue");
    // red, as the conventions say: an agent that never checked in can't seal
    expect(within(never).getByText("Never Checked In")).toHaveClass(
      "text-destructive",
    );
    // the badge says it all
    expect(
      within(never).queryByRole("button", { name: /issue/ }),
    ).not.toBeInTheDocument();
    expect(details("use2-blue")).not.toHaveTextContent(/Issues/);
    // registered capabilities still show for an agent that never checked in
    expect(within(details("use2-blue")).getByText("seal")).toBeInTheDocument();
    // capabilities are sorted, and the region is a tag
    expect(
      within(
        within(details("use1-blue")).getByRole("list", {
          name: "Capabilities",
        }),
      )
        .getAllByRole("listitem")
        .map((li) => li.textContent),
    ).toEqual(["keys", "seal"]);
    expect(within(never).getByText("use2")).toHaveClass("font-mono");
  });

  it("says when no agent has checked in yet", async () => {
    renderFleet({
      env: "prod",
      env_key: null,
      keys_in_sync: false,
      key_limit: 250,
      keys: [],
      agents: [
        agent({
          id: "use1-blue",
          checked_in: false,
          healthy: false,
          in_scope: false,
          last_checkin: undefined,
        }),
      ],
    });
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/no agent has checked in yet/i);
    expect(alert).not.toHaveTextContent(/missing column/i);
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
    await screen.findByRole("region", { name: "Env key" });
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
    expect(within(env).getByText("Env Key")).toBeInTheDocument();
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
    expect(revoked).toHaveTextContent("by alice 2h ago");
    expect(within(revoked).getByText("2h ago")).toHaveAttribute(
      "title",
      expect.stringMatching(/^Revoked by alice, /),
    );
    // a visible header over the icons, aligned with them
    const actions = screen.getByRole("columnheader", { name: "Actions" });
    expect(actions).not.toHaveClass("sr-only");
    expect(actions.querySelector(".sr-only")).toBeNull();
    expect(actions).toHaveClass("text-right");
    // the same three actions on every row; those that do not apply say why
    expect(keyActions(KEY_B.fingerprint)).toEqual({
      Revoke: "enabled",
      Delete: "Revoke the key first.",
      Reinstate: "Not revoked.",
    });
    expect(keyActions(KEY_C.fingerprint)).toEqual({
      Revoke: "Already revoked.",
      Delete: "It cannot be deleted now.",
      Reinstate: "enabled",
    });
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
    expect(within(row).getByText("Future-Dated")).toBeInTheDocument();
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
      name: "Revoke This Key?",
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

    fireEvent.click(within(dialog).getByRole("button", { name: "Revoke Key" }));
    await waitFor(() =>
      expect(
        screen.queryByRole("dialog", { name: "Revoke This Key?" }),
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
    fireEvent.click(within(dialog).getByRole("button", { name: "Revoke Key" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "Could not revoke the key: only admins can do this",
    );
  });

  it("reinstates a revoked key after a dialog, with its fingerprint in the URL-safe alphabet", async () => {
    const api = renderFleet(keyedFleet());
    await screen.findByRole("heading", { name: "Keys" });
    fireEvent.click(
      within(keyRow(KEY_C.fingerprint)).getByRole("button", {
        name: /reinstate key/i,
      }),
    );
    const dialog = await screen.findByRole("dialog", {
      name: "Reinstate This Key?",
    });
    // what reinstating does: restores it, and may make it the env key
    expect(dialog).toHaveTextContent(/restored to every cluster/i);
    expect(dialog).toHaveTextContent(/may become the env key/i);
    // nothing is sent until it is confirmed
    expect(api.calls.filter((c) => c.method === "POST")).toHaveLength(0);
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Reinstate Key" }),
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

  it("says when every shared key is revoked and a new key is needed", async () => {
    renderFleet(
      keyedFleet({
        env_key: null,
        keys_in_sync: false,
        no_usable_key: true,
      }),
    );
    const banner = await screen.findByRole("region", {
      name: "Env key",
    });
    const alert = within(banner).getByRole("alert");
    expect(alert).toHaveTextContent("New Key Needed");
    expect(alert).toHaveTextContent("Sealing Unavailable");
    expect(alert).toHaveTextContent(/revoked or not valid yet/);
    expect(alert).not.toHaveTextContent(/keys out of sync/i);
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
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/could not load the fleet/i);
    // the server's message, as a sentence
    expect(alert).toHaveTextContent(
      "The server encountered an error — please try again.",
    );
  });
});

/** An agent that counts key references, with a count a minute old. */
function countingAgent(
  overrides: Partial<FleetAgent> & { id: string },
): FleetAgent {
  return agent({
    keys: [KEY_A, KEY_B],
    keys_reported: 2,
    registered_capabilities: CLEANUP_CAPABILITIES,
    capabilities: CLEANUP_CAPABILITIES,
    key_usage: keyUsage(),
    ...overrides,
  });
}

/** Two clusters that count references, as keyedFleet's agents. */
const COUNTING = [
  countingAgent({ id: "use1-blue" }),
  countingAgent({ id: "use2-blue", region: "use2" }),
];

/** KEY_C, revoked two hours ago and counted unreferenced in both clusters. */
function revokedKey(overrides: Partial<FleetKey> = {}) {
  return fleetKey(KEY_C, {
    holders: ["use1-blue", "use2-blue"],
    status: "revoked",
    revoked_by: "alice",
    revoked_at: iso(2 * 3_600_000),
    references: references([
      counted("use1-blue", 0),
      counted("use2-blue", 0, 0, 20 * 60_000),
    ]),
    deletable: true,
    ...overrides,
  });
}

/** KEY_C, deleted by alice two hours ago; purged in 30 days from then. */
function deletedKey(overrides: Partial<FleetKey> = {}) {
  return revokedKey({
    status: "deleted",
    revoked_by: "bob",
    revoked_at: iso(3 * 24 * 3_600_000),
    deleted_by: "alice",
    deleted_at: iso(2 * 3_600_000),
    purge_at: iso(2 * 3_600_000 - 30 * 24 * 3_600_000),
    holders: [],
    deletable: false,
    ...overrides,
  });
}

/** The fleet with counting agents and these keys besides the env key. */
function countedFleet(...keys: FleetKey[]): Fleet {
  return keyedFleet({
    agents: COUNTING,
    keys: [
      fleetKey(KEY_B, {
        holders: ["use1-blue", "use2-blue"],
        env_key: true,
        escrow_copies: 2,
        references: references([
          counted("use1-blue", 8, 3),
          counted("use2-blue", 4, 1),
        ]),
      }),
      ...keys,
    ],
  });
}

/** A key's References cell: the toggle of its count per cluster. */
function referencesToggle(fingerprint: string) {
  return within(keyRow(fingerprint)).getByRole("button", {
    expanded: false,
  });
}

describe("FleetView key references and deletion", () => {
  const originalAdapter = apiClient.defaults.adapter;
  afterEach(() => {
    apiClient.defaults.adapter = originalAdapter;
  });

  it("shows each key's references, with the count per cluster on demand", async () => {
    renderFleet(
      countedFleet(
        fleetKey(KEY_A, {
          holders: ["use1-blue", "use2-blue"],
          references: references([
            counted("use1-blue", 0),
            counted("use2-blue", 0),
          ]),
        }),
      ),
    );
    await screen.findByRole("heading", { name: "Keys" });
    // every agent counts, so nothing needs explaining
    expect(
      screen.queryByRole("status", { name: "References" }),
    ).not.toBeInTheDocument();

    // zero in every cluster reads as none
    expect(
      within(keyRow(KEY_A.fingerprint)).getByRole("button", { name: "None" }),
    ).toBeInTheDocument();

    // a button, not a hover title: it works with a keyboard and a tap
    const toggle = within(keyRow(KEY_B.fingerprint)).getByRole("button", {
      name: "12 values, in 4 SealedSecrets",
    });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    const perCluster = screen.getByRole("table", {
      name: /^References to key SHA256:ZZZZzzzzYYYY… per cluster$/,
    });
    // the row it controls follows the key's
    expect(perCluster.closest("tr")).toHaveAttribute(
      "id",
      toggle.getAttribute("aria-controls"),
    );
    const blue = within(perCluster)
      .getByRole("rowheader", { name: /^use1-blue/ })
      .closest("tr") as HTMLElement;
    expect(blue).toHaveTextContent("use1-blueblue83");
    const when = within(blue).getByText("1m ago");
    expect(when).toHaveAttribute("title", expect.stringMatching(/^Counted /));
    expect(
      within(perCluster).getByRole("rowheader", { name: /^use2-blue/ }),
    ).toBeInTheDocument();

    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(
      screen.queryByRole("table", { name: /per cluster/ }),
    ).not.toBeInTheDocument();
  });

  it("says a count is unknown or a lower bound when a cluster did not count, and why", async () => {
    renderFleet(
      keyedFleet({
        agents: [
          countingAgent({ id: "use1-blue" }),
          // no cleanup capability
          agent({ id: "use2-green", region: "use2", cluster: "green" }),
          countingAgent({
            id: "use1-red",
            cluster: "red",
            key_usage: keyUsage({
              error: "cannot list sealedsecrets.bitnami.com: forbidden",
            }),
          }),
          countingAgent({
            id: "use2-red",
            region: "use2",
            cluster: "red",
            key_usage: keyUsage({ counted_at: iso(2 * 3_600_000) }),
          }),
        ],
        keys: [
          fleetKey(KEY_B, {
            env_key: true,
            references: references(
              [counted("use1-blue", 8, 3)],
              ["use2-green"],
            ),
          }),
          fleetKey(KEY_A, {
            references: references([counted("use1-blue", 0)], ["use2-green"]),
          }),
          revokedKey({
            references: references([], ["use2-green", "use1-red", "use2-red"]),
            deletable: false,
            delete_blocked:
              "use2-green does not count references: it lacks the cleanup capability.",
          }),
        ],
      }),
    );
    await screen.findByRole("heading", { name: "Keys" });

    // a lower bound, naming the cluster left out
    expect(referencesToggle(KEY_B.fingerprint)).toHaveAccessibleName(
      "At least 8 values, not counted in use2-green",
    );
    expect(
      within(referencesToggle(KEY_B.fingerprint)).getByText("use2-green"),
    ).toHaveClass("font-mono");
    // a 0 with a cluster left out is unknown, never a bare 0 or none
    const partial = referencesToggle(KEY_A.fingerprint);
    expect(partial).toHaveAccessibleName("Unknown, not counted in use2-green");
    expect(partial).not.toHaveTextContent(/\b0\b|none/i);
    // many clusters left out are counted, then named per cluster
    const unknown = referencesToggle(KEY_C.fingerprint);
    expect(unknown).toHaveAccessibleName("Unknown, not counted in 3 clusters");
    fireEvent.click(unknown);
    const detail = document.getElementById(
      unknown.getAttribute("aria-controls")!,
    )!;
    expect(detail).toHaveTextContent(
      "These clusters did not count, so the count is unknown:",
    );
    const reasons = within(detail)
      .getAllByRole("listitem")
      .map((li) => li.textContent);
    expect(reasons).toEqual([
      "use2-green: no cleanup capability",
      "use1-red: the count failed: cannot list sealedsecrets.bitnami.com: forbidden",
      "use2-red: last counted 2h ago",
    ]);
    // no per-cluster table when no cluster counted
    expect(within(detail).queryByRole("table")).not.toBeInTheDocument();

    fireEvent.click(referencesToggle(KEY_B.fingerprint));
    expect(
      screen.getByText("These clusters did not count, so there may be more:"),
    ).toBeInTheDocument();
  });

  it("explains an empty References column when no agent counts", async () => {
    renderFleet(
      keyedFleet({
        keys: [
          fleetKey(KEY_B, {
            env_key: true,
            references: references([], ["use1-blue", "use2-blue"]),
          }),
        ],
      }),
    );
    const note = await screen.findByRole("status", { name: "References" });
    expect(note).toHaveTextContent(
      "No cluster counts key references, so the References column is empty and no key can be deleted.",
    );
    expect(within(note).getByText("cleanup")).toHaveClass("font-mono");
    // one note, not a toggle per row
    const row = keyRow(KEY_B.fingerprint);
    expect(within(row).getByLabelText("not counted")).toHaveTextContent("—");
    expect(
      within(row).queryByRole("button", { expanded: false }),
    ).not.toBeInTheDocument();
  });

  it("lists deleted keys in a table of their own, without references", async () => {
    renderFleet(countedFleet(revokedKey(), deletedKey({ ...KEY_A })));
    // the keys in use, and the deleted ones apart
    expect(await screen.findByText("2 keys, 1 revoked")).toBeInTheDocument();
    const keys = screen.getByRole("table", {
      name: "Sealing keys in this env",
    });
    expect(within(keys).queryByTitle(KEY_A.fingerprint)).toBeNull();
    const section = screen.getByRole("region", { name: "Deleted Keys" });
    expect(within(section).getByText("1 key")).toBeInTheDocument();
    const deleted = within(section).getByRole("table", {
      name: "Deleted sealing keys in this env",
    });
    expect(
      within(deleted)
        .getAllByRole("columnheader")
        .map((h) => h.textContent),
    ).toEqual([
      "Key",
      "Valid From",
      "Deleted",
      "Escrow",
      "Clusters",
      "Actions",
    ]);
    expect(within(deleted).getByTitle(KEY_A.fingerprint)).toBeInTheDocument();
  });

  it("shows no deleted keys section without deleted keys", async () => {
    renderFleet(countedFleet(revokedKey()));
    expect(await screen.findByText("2 keys, 1 revoked")).toBeInTheDocument();
    expect(
      screen.queryByRole("region", { name: "Deleted Keys" }),
    ).not.toBeInTheDocument();
  });

  it("offers Revoke, Delete and Reinstate on every key in use, Reinstate alone on a deleted one, and a grayed-out one opens nothing", async () => {
    const api = renderFleet(
      countedFleet(
        revokedKey(),
        deletedKey({
          ...KEY_A,
          purged: true,
          delete_blocked: "The key is already deleted.",
        }),
      ),
    );
    await screen.findByRole("heading", { name: "Keys" });
    for (const fp of [
      KEY_B.fingerprint,
      KEY_C.fingerprint,
      KEY_A.fingerprint,
    ]) {
      const buttons = within(keyRow(fp))
        .getAllByRole("button")
        .filter((b) =>
          /^(Revoke|Delete|Reinstate) key /.test(b.ariaLabel ?? ""),
        );
      // the same icons in the same places on every row of a table
      expect(buttons.map((b) => b.ariaLabel?.split(" ")[0])).toEqual(
        fp === KEY_A.fingerprint
          ? ["Reinstate"]
          : ["Revoke", "Delete", "Reinstate"],
      );
      for (const b of buttons) {
        expect(b).toHaveClass("h-9", "w-9");
        expect(b).not.toHaveTextContent(/\w/);
        if (b.getAttribute("aria-disabled") !== "true") continue;
        expect(b).not.toBeDisabled();
        fireEvent.click(b);
        expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
      }
    }
    expect(keyActions(KEY_A.fingerprint)).toEqual({
      Reinstate: "Escrowed copies were purged.",
    });
    expect(api.calls.filter((c) => c.method === "POST")).toHaveLength(0);
  });

  it("says a key with references cannot be deleted", async () => {
    renderFleet(
      countedFleet(
        revokedKey({
          references: references([
            counted("use1-blue", 2, 1),
            counted("use2-blue", 1, 1),
          ]),
          deletable: false,
          delete_blocked: undefined,
        }),
      ),
    );
    await screen.findByRole("heading", { name: "Keys" });
    expect(keyActions(KEY_C.fingerprint).Delete).toBe(
      "3 values are sealed with it.",
    );
  });

  it("deletes a revoked key nothing refers to, after a dialog that says what deleting does", async () => {
    const api = renderFleet(countedFleet(revokedKey()));
    await screen.findByRole("heading", { name: "Keys" });
    const row = keyRow(KEY_C.fingerprint);
    expect(keyActions(KEY_C.fingerprint)).toEqual({
      Revoke: "Already revoked.",
      Delete: "enabled",
      Reinstate: "enabled",
    });
    fireEvent.click(within(row).getByRole("button", { name: /delete key/i }));

    const dialog = await screen.findByRole("dialog", {
      name: "Delete This Key?",
    });
    // what it does
    expect(dialog).toHaveTextContent(
      "SHA256:Cc+c/cCCddDD… is removed from every cluster, and each controller restarts once",
    );
    // what it rests on, and how old that is
    expect(dialog).toHaveTextContent(
      "No cluster refers to it. Every cluster counted the values in its SealedSecrets, and none was sealed with it; the oldest count was taken 20m ago.",
    );
    expect(within(dialog).getByText("20m ago")).toHaveAttribute(
      "title",
      expect.stringMatching(/^Counted /),
    );
    // how long it can be undone
    expect(dialog).toHaveTextContent(
      "Its escrowed copies are kept until then, and Reinstate restores the key to every cluster. After that it is gone for good.",
    );
    expect(dialog).toHaveTextContent(/undo it for 30 days/);
    // what the count cannot see
    expect(dialog).toHaveTextContent(
      /values in git that are not deployed to any cluster/,
    );
    expect(dialog).toHaveTextContent(
      /pull requests opened before the key was revoked that merge later/,
    );
    expect(dialog).toHaveTextContent(/watch the clusters' unmatched counts/);
    // nothing is sent until it is confirmed
    expect(api.calls.filter((c) => c.method === "POST")).toHaveLength(0);

    const confirm = within(dialog).getByRole("button", { name: "Delete Key" });
    expect(confirm).toHaveClass("bg-destructive");
    fireEvent.click(confirm);
    await waitFor(() =>
      expect(
        screen.queryByRole("dialog", { name: "Delete This Key?" }),
      ).not.toBeInTheDocument(),
    );
    expect(api.calls.filter((c) => c.method === "POST")).toEqual([
      expect.objectContaining({
        url: "/keys/SHA256%3ACc-c_cCCddDDeeEEffFFggGGhhHHiiIIjjJJkkKKllL/delete",
        env: "dev",
        csrf: ADMIN.csrf_token,
      }),
    ]);
    // a toast names the key, in monospace, and how to undo it
    const toast = await screen.findByText(/^Deleted/);
    expect(within(toast).getByText("SHA256:Cc+c/cCCddDD…")).toHaveClass(
      "font-mono",
    );
    expect(
      screen.getByText(/Reinstate it within 30 days to undo this/),
    ).toBeInTheDocument();
    // the fleet is read again
    await waitFor(() =>
      expect(api.calls.filter((c) => c.url === "/fleet")).toHaveLength(2),
    );
  });

  it("shows the server's refusal in the delete dialog", async () => {
    renderFleet(countedFleet(revokedKey()), undefined, {
      keyStatusError: {
        status: 409,
        error:
          "use2-blue has not counted references since the key was revoked.",
      },
    });
    await screen.findByRole("heading", { name: "Keys" });
    fireEvent.click(
      within(keyRow(KEY_C.fingerprint)).getByRole("button", {
        name: /delete key/i,
      }),
    );
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete Key" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "Could not delete the key: use2-blue has not counted references since the key was revoked.",
    );
    // the dialog stays, so the reason can be read
    expect(dialog).toBeInTheDocument();
  });

  it("says why a revoked key cannot be deleted, on focus and on a tap", async () => {
    const why =
      "use2-blue has not counted references since the key was revoked.";
    const api = renderFleet(
      countedFleet(revokedKey({ deletable: false, delete_blocked: why })),
    );
    await screen.findByRole("heading", { name: "Keys" });
    const del = within(keyRow(KEY_C.fingerprint)).getByRole("button", {
      name: /delete key/i,
    });
    // disabled, but focusable, with the reason as its description
    expect(del).toHaveAttribute("aria-disabled", "true");
    expect(del).not.toBeDisabled();
    expect(del).toHaveAccessibleDescription(why);
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();

    fireEvent.focus(del);
    await waitFor(() => expect(tooltipShown()).toContain(why));
    fireEvent.blur(del);
    await waitFor(() => expect(tooltipShown()).toBeUndefined());

    // a tap shows the reason, and does nothing else
    fireEvent.click(del);
    await waitFor(() => expect(tooltipShown()).toContain(why));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(api.calls.filter((c) => c.method === "POST")).toHaveLength(0);
  });

  it("shows a deleted key being removed from clusters, and reinstates it from escrow", async () => {
    const api = renderFleet(
      countedFleet(deletedKey({ holders: ["use2-blue"] })),
    );
    await screen.findByRole("heading", { name: "Deleted Keys" });
    const row = keyRow(KEY_C.fingerprint);
    expect(row.closest("table")).toHaveAccessibleName(
      "Deleted sealing keys in this env",
    );
    expect(row).toHaveTextContent("by alice 2h ago");
    expect(within(row).getByText("2h ago")).toHaveAttribute(
      "title",
      expect.stringMatching(/^Deleted by alice, /),
    );
    expect(row).toHaveTextContent("purged in 29d");
    expect(within(row).getByText("in 29d")).toHaveAttribute(
      "title",
      expect.stringMatching(
        /^Escrowed copies purged .*; it can be reinstated until then$/,
      ),
    );
    expect(within(row).getByText("removing from 1 cluster")).toHaveAttribute(
      "title",
      "use2-blue",
    );
    expect(keyActions(KEY_C.fingerprint)).toEqual({ Reinstate: "enabled" });

    fireEvent.click(
      within(row).getByRole("button", { name: /reinstate key/i }),
    );
    const dialog = await screen.findByRole("dialog", {
      name: "Reinstate This Deleted Key?",
    });
    expect(dialog).toHaveTextContent(
      /key sync restores it from escrow to every cluster; each controller restarts once to load it/,
    );
    expect(dialog).toHaveTextContent(/kept rather than purged in 29d/);
    expect(dialog).toHaveTextContent(/may become the env key/i);
    expect(dialog).toHaveTextContent(/only if it was deleted by mistake/);
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Reinstate Key" }),
    );
    await waitFor(() =>
      expect(api.calls.filter((c) => c.method === "POST")).toEqual([
        expect.objectContaining({
          url: "/keys/SHA256%3ACc-c_cCCddDDeeEEffFFggGGhhHHiiIIjjJJkkKKllL/reinstate",
          csrf: ADMIN.csrf_token,
        }),
      ]),
    );
    expect(
      await screen.findByText(
        "Key sync restores it to every cluster from escrow.",
      ),
    ).toBeInTheDocument();
  });

  it("shows a deleted key no cluster holds, waiting for its escrow purge", async () => {
    renderFleet(countedFleet(deletedKey()));
    await screen.findByRole("heading", { name: "Deleted Keys" });
    const row = keyRow(KEY_C.fingerprint);
    expect(row).toHaveTextContent("purged in 29d");
    expect(row).not.toHaveTextContent(/removing/);
    expect(row).toHaveTextContent("removed from every cluster");
    expect(keyActions(KEY_C.fingerprint).Reinstate).toBe("enabled");
  });

  it("offers nothing for a purged key, and says why", async () => {
    renderFleet(
      countedFleet(
        deletedKey({
          purged: true,
          purge_at: iso(2 * 24 * 3_600_000),
          // still listed while a cluster that was down holds it
          holders: ["use1-blue"],
        }),
      ),
    );
    await screen.findByRole("heading", { name: "Keys" });
    const row = keyRow(KEY_C.fingerprint);
    expect(row).toHaveTextContent("purged 2d ago");
    expect(within(row).getByText("2d ago")).toHaveAttribute(
      "title",
      expect.stringMatching(/: it cannot be reinstated$/),
    );
    expect(row).toHaveTextContent("removing from 1 cluster");
    expect(keyActions(KEY_C.fingerprint)).toEqual({
      Reinstate: "Escrowed copies were purged.",
    });
  });

  it("shows the server's refusal to reinstate a key purged meanwhile", async () => {
    renderFleet(countedFleet(deletedKey()), undefined, {
      keyStatusError: {
        status: 409,
        error: "Its escrowed copies were purged; it cannot be reinstated.",
      },
    });
    await screen.findByRole("heading", { name: "Keys" });
    fireEvent.click(
      within(keyRow(KEY_C.fingerprint)).getByRole("button", {
        name: /reinstate key/i,
      }),
    );
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Reinstate Key" }),
    );
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "Could not reinstate the key: Its escrowed copies were purged; it cannot be reinstated.",
    );
  });

  it("shows what each agent counted", async () => {
    renderFleet(
      keyedFleet({
        agents: [
          countingAgent({ id: "use1-blue" }),
          countingAgent({
            id: "use2-blue",
            region: "use2",
            key_usage: keyUsage({
              values: 1,
              sealed_secrets: 1,
              unmatched: 3,
              namespaces: ["dev-use2-blue-apps", "billing"],
              counted_at: iso(5 * 60_000),
            }),
          }),
          countingAgent({
            id: "use1-green",
            key_usage: keyUsage({
              error: "cannot list sealedsecrets.bitnami.com: forbidden",
            }),
          }),
          countingAgent({ id: "use2-green", key_usage: undefined }),
          agent({ id: "use1-red" }),
          agent({
            id: "use2-red",
            checked_in: false,
            in_scope: false,
            last_checkin: undefined,
            capabilities: undefined,
          }),
        ],
      }),
    );
    await screen.findByRole("heading", { name: "Keys" });

    // the counts on one line, and when and where in the details
    const all = row("use1-blue");
    expect(within(all).getByText("12 values")).toHaveAttribute(
      "title",
      "Counted 1m ago",
    );
    expect(within(all).getByText("in 4 SealedSecrets")).toBeInTheDocument();
    expect(within(all).queryByText(/unmatched/)).not.toBeInTheDocument();
    const allDetails = details("use1-blue");
    expect(allDetails).toHaveTextContent("Counted 1m ago, in every namespace");
    expect(within(allDetails).getByText("1m ago")).toHaveAttribute(
      "title",
      expect.stringMatching(/^Counted /),
    );

    const some = row("use2-blue");
    expect(within(some).getByText("1 value")).toBeInTheDocument();
    expect(within(some).getByText("in 1 SealedSecret")).toBeInTheDocument();
    expect(some).not.toHaveTextContent(/namespace/);
    // values the controller cannot decrypt need attention
    expect(within(some).getByText("3 unmatched")).toHaveClass("text-warning");
    // the namespaces it counted in, by name
    expect(details("use2-blue")).toHaveTextContent(
      "Counted 5m ago, in 2 namespaces: dev-use2-blue-apps, billing",
    );

    const failed = row("use1-green");
    expect(within(failed).getByText(/^Count failed/)).toHaveClass(
      "text-destructive",
    );
    expect(failed).not.toHaveTextContent(/SealedSecret/);
    expect(details("use1-green")).toHaveTextContent(
      /Failed 1m ago: Cannot list sealedsecrets\.bitnami\.com: forbidden\./,
    );

    expect(row("use2-green")).toHaveTextContent("Not counted yet");
    expect(within(row("use1-red")).getByText("Doesn't count")).toHaveAttribute(
      "title",
      expect.stringMatching(/cleanup capability/),
    );
    expect(row("use2-red")).not.toHaveTextContent(/count/i);
  });
});

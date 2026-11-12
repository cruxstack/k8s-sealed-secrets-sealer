import { describe, it, expect, afterEach, beforeEach } from "vitest";
import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { AxiosError, type AxiosAdapter } from "axios";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRouter,
  RouterProvider,
} from "@tanstack/react-router";
import apiClient from "@/api/client";
import type { FileListing, PendingChange } from "@/api/types";
import { ThemeProvider } from "@/lib/theme-provider";
import { routeTree } from "@/routeTree.gen";
import {
  ADMIN,
  KEY_A,
  KEY_B,
  ME,
  REPO_PLATFORM,
  SESSION,
  STATUS,
  fakeApi,
  fileReseal,
  iso,
  listing,
  type FakeApi,
} from "@/test/fake-api";
import { sealPolling } from "./SealForm";
import { resealPolling } from "./ResealFile";

function renderAt(path: string, api: Pick<FakeApi, "adapter">) {
  apiClient.defaults.adapter = api.adapter;
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const router = createRouter({
    routeTree,
    context: { queryClient },
    history: createMemoryHistory({ initialEntries: [path] }),
  });
  render(
    <ThemeProvider defaultTheme="light" storageKey="test-theme">
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </ThemeProvider>,
  );
  return router;
}

const PAGE = "/dev/secrets/example-org/apps";
const APPS = "/repos/example-org/apps";
const BILLING = "deploy/billing/sealed-secret.yaml";

/** The billing file with three values: two in use1, one in use2. */
function billing(overrides: Partial<FileListing> = {}): FileListing {
  const base = listing();
  const [file, ...rest] = base.files;
  return {
    ...base,
    files: [
      {
        ...file!,
        documents: [
          { ...file!.documents![0]!, keys: ["api-key", "db-password"] },
          file!.documents![1]!,
        ],
      },
      ...rest,
    ],
    ...overrides,
  };
}

/** A value sealed in this session for use1's document. */
const SEALED: PendingChange = {
  id: "change-db-password",
  path: BILLING,
  key: "db-password",
  targets: [
    {
      index: 0,
      namespace: "dev-use1-blue-apps",
      name: "billing",
      scope: "strict",
      region: "use1",
    },
  ],
  sealed_at: iso(60_000),
  sealed_by: { id: "dev-use1-blue", cluster: "dev-use1-blue" },
  fingerprint: KEY_B.fingerprint,
};

/** api-key, resealed off KEY_A onto the env key in both documents. */
const RESEALED: PendingChange = {
  id: "change-reseal-api-key",
  path: BILLING,
  key: "api-key",
  kind: "reseal",
  resealed_from: [KEY_A.fingerprint],
  targets: [
    {
      index: 0,
      namespace: "dev-use1-blue-apps",
      name: "billing",
      scope: "strict",
      region: "use1",
    },
    {
      index: 2,
      namespace: "dev-use2-blue-apps",
      name: "billing",
      scope: "strict",
      region: "use2",
    },
  ],
  sealed_at: iso(500),
  sealed_by: { id: "dev-use1-blue", cluster: "dev-use1-blue" },
  fingerprint: KEY_B.fingerprint,
};

/** The billing file's panel, once its "Reseal All" is there. */
async function panel() {
  const region = await screen.findByRole("region", { name: BILLING });
  await within(region).findByRole("button", { name: /Reseal All/ });
  return region;
}

/** "enabled", or the reason a grayed-out button gives. */
function availability(button: HTMLElement): string {
  if (button.getAttribute("aria-disabled") !== "true") return "enabled";
  const id = (button.getAttribute("aria-describedby") ?? "").split(" ")[0]!;
  return document.getElementById(id)?.textContent ?? "no reason";
}

describe("Reseal All", () => {
  const originalAdapter = apiClient.defaults.adapter;
  beforeEach(() => {
    sealPolling.intervalMs = 5;
    resealPolling.intervalMs = 5;
    resealPolling.maxBackoffMs = 20;
  });
  afterEach(() => {
    apiClient.defaults.adapter = originalAdapter;
  });

  it("reseals a file's values onto the env key, as pending changes", async () => {
    const api = fakeApi({
      me: ADMIN,
      files: { "example-org/apps": billing() },
      sessions: {
        "example-org/apps": {
          ...SESSION,
          pending_changes: 1,
          changes: [SEALED],
        },
      },
      fileReseals: [
        fileReseal({
          status: "resealing",
          values: { total: 3, resealed: 0, current: 1, failed: 0, pending: 1 },
        }),
        fileReseal({
          status: "done",
          values: { total: 3, resealed: 1, current: 1, failed: 0, pending: 1 },
          change_ids: [RESEALED.id],
        }),
      ],
      resealChanges: [RESEALED],
    });
    renderAt(PAGE, api);
    const file = await panel();
    const button = within(file).getByRole("button", { name: /Reseal All/ });
    expect(availability(button)).toBe("enabled");
    fireEvent.click(button);

    // what it does and doesn't do, before it starts
    const ask = await screen.findByRole("dialog", {
      name: "Reseal All Values in This File?",
    });
    expect(ask).toHaveTextContent(
      `${BILLING} holds 3 values in 2 documents for the dev env.`,
    );
    expect(ask).toHaveTextContent(
      "Each one sealed with an older key is re-encrypted for the env key",
    );
    expect(ask).toHaveTextContent("They become pending changes.");
    expect(ask).toHaveTextContent(
      "1 value has a pending change in your session, so it is left alone.",
    );
    expect(ask).toHaveTextContent(
      "Values already on the env key don't change.",
    );
    expect(ask).toHaveTextContent("It doesn't rotate values.");
    fireEvent.click(within(ask).getByRole("button", { name: "Reseal All" }));

    // its progress, then what it did
    const progress = await screen.findByRole("progressbar", {
      name: "Values checked",
    });
    expect(progress).toHaveAttribute("aria-valuemax", "2");
    await screen.findByText("Resealing in dev-use1-blue: 1 of 2 values…");
    const done = await screen.findByRole("dialog", {
      name: "Resealed 1 Value",
    });
    const summary = within(done).getByRole("list", { name: "Reseal summary" });
    expect(
      within(summary)
        .getAllByRole("listitem")
        .map((li) => li.textContent),
    ).toEqual([
      "1 resealed, now in your pending changes",
      "1 already on the env key",
      "1 left out: it has a pending change",
    ]);
    const post = api.calls.find((c) => c.url.endsWith("/reseals"));
    expect(post).toMatchObject({
      method: "POST",
      url: `${APPS}/session/${SESSION.id}/reseals`,
      csrf: ADMIN.csrf_token,
      body: { path: BILLING },
    });
    fireEvent.click(within(done).getByRole("button", { name: "Done" }));

    // the change reads as a reseal: its marker, and the key it came off
    const pending = screen.getByRole("region", { name: /pending changes/i });
    const item = (await within(pending).findByText("api-key")).closest(
      "li",
    ) as HTMLElement;
    expect(within(item).getByText("Resealed")).toHaveAttribute(
      "title",
      expect.stringContaining(KEY_A.fingerprint),
    );
    expect(
      within(item).getByTitle(`Resealed from ${KEY_A.fingerprint}`),
    ).toHaveTextContent("from SHA256:AAAAaaaa…");
    expect(within(item).getByTitle(/^Resealed by dev-use1-blue/)).toBeVisible();
    // a newly sealed value has neither
    const sealed = within(pending)
      .getByText("db-password")
      .closest("li") as HTMLElement;
    expect(within(sealed).queryByText("Resealed")).not.toBeInTheDocument();
    expect(within(sealed).getByTitle(/^Sealed by dev-use1-blue/)).toBeVisible();
    // the key list says the file's value moved, not that a new one waits
    const keys = within(file).getByRole("list", { name: "Keys" });
    expect(
      within(keys).getByRole("button", { name: /^api-key/ }),
    ).toHaveTextContent("Resealed, in your pending changes");
    // and the pull request says what it writes, counting values as its
    // title does: one per document a key was resealed in
    fireEvent.click(
      within(pending).getByRole("button", { name: "Open Pull Request" }),
    );
    expect(
      await screen.findByRole("dialog", { name: "Open a Pull Request?" }),
    ).toHaveTextContent(
      "writes 1 sealed value and 2 resealed values into 1 file",
    );
  });

  it("opens a session first when there is none", async () => {
    const api = fakeApi({
      me: ADMIN,
      files: { "example-org/apps": billing() },
      resealChanges: [RESEALED],
    });
    renderAt(PAGE, api);
    fireEvent.click(
      within(await panel()).getByRole("button", { name: /Reseal All/ }),
    );
    const ask = await screen.findByRole("dialog");
    expect(ask).toHaveTextContent(
      "Values with a pending change in your session are left alone.",
    );
    fireEvent.click(within(ask).getByRole("button", { name: "Reseal All" }));
    await screen.findByRole("dialog", { name: "Resealed 1 Value" });
    expect(
      api.calls.filter((c) => c.method === "POST").map((c) => c.url),
    ).toEqual([`${APPS}/session`, `${APPS}/session/${SESSION.id}/reseals`]);
    expect(api.calls.find((c) => c.method === "POST")?.body).toEqual({
      commit: listing().commit,
    });
  });

  it("lists the values that failed, and why", async () => {
    const api = fakeApi({
      me: ADMIN,
      files: { "example-org/apps": billing() },
      fileReseals: [
        fileReseal({
          status: "done",
          values: { total: 3, resealed: 0, current: 2, failed: 1, pending: 0 },
          failures: [
            {
              key: "api-key",
              document: 2,
              region: "use2",
              error: "no key in dev-use1-blue opens it",
            },
          ],
        }),
      ],
    });
    renderAt(PAGE, api);
    fireEvent.click(
      within(await panel()).getByRole("button", { name: /Reseal All/ }),
    );
    fireEvent.click(
      within(await screen.findByRole("dialog")).getByRole("button", {
        name: "Reseal All",
      }),
    );
    const done = await screen.findByRole("dialog", {
      name: "No Value Was Resealed",
    });
    expect(within(done).getByText("1 failed")).toHaveClass("text-destructive");
    const failures = within(done).getByRole("list", {
      name: "Values that could not be resealed",
    });
    expect(failures).toHaveTextContent(
      "api-keydocument #2use2No key in dev-use1-blue opens it.",
    );
  });

  it("says when no agent answered in time", async () => {
    renderAt(
      PAGE,
      fakeApi({
        me: ADMIN,
        files: { "example-org/apps": billing() },
        fileReseals: [
          fileReseal({
            status: "expired",
            values: {
              total: 3,
              resealed: 0,
              current: 0,
              failed: 0,
              pending: 0,
            },
            error: "no agent answered in time",
          }),
        ],
      }),
    );
    fireEvent.click(
      within(await panel()).getByRole("button", { name: /Reseal All/ }),
    );
    fireEvent.click(
      within(await screen.findByRole("dialog")).getByRole("button", {
        name: "Reseal All",
      }),
    );
    const done = await screen.findByRole("dialog", {
      name: "Resealing Timed Out",
    });
    expect(within(done).getByRole("alert")).toHaveTextContent(
      "No agent answered in time.",
    );
  });

  it("shows the control plane's refusal, ready to try again", async () => {
    renderAt(
      PAGE,
      fakeApi({
        me: ADMIN,
        files: { "example-org/apps": billing() },
        fileResealError: {
          status: 409,
          error:
            "3 keys need resealing, and the session takes 50 changes: remove some first",
        },
      }),
    );
    fireEvent.click(
      within(await panel()).getByRole("button", { name: /Reseal All/ }),
    );
    const ask = await screen.findByRole("dialog");
    fireEvent.click(within(ask).getByRole("button", { name: "Reseal All" }));
    expect(await within(ask).findByRole("alert")).toHaveTextContent(
      "Could not reseal the file: 3 keys need resealing, and the session takes 50 changes: remove some first.",
    );
    expect(
      within(ask).getByRole("button", { name: "Reseal All" }),
    ).toBeVisible();
  });

  it("says when it finishes after its dialog was closed", async () => {
    // slow enough to close the dialog while it waits
    resealPolling.intervalMs = 40;
    renderAt(
      PAGE,
      fakeApi({
        me: ADMIN,
        files: { "example-org/apps": billing() },
        fileReseals: [
          fileReseal({ status: "queued" }),
          fileReseal({ status: "queued" }),
          fileReseal({ status: "queued" }),
          fileReseal({ status: "done" }),
        ],
      }),
    );
    const file = await panel();
    fireEvent.click(within(file).getByRole("button", { name: /Reseal All/ }));
    fireEvent.click(
      within(await screen.findByRole("dialog")).getByRole("button", {
        name: "Reseal All",
      }),
    );
    const running = await screen.findByRole("dialog", { name: "Resealing…" });
    expect(running).toHaveTextContent("Waiting for dev-use1-blue…");
    expect(running).toHaveTextContent(
      "You can close this. The resealed values join your pending changes when it finishes.",
    );
    fireEvent.click(within(running).getByText("Close", { selector: "button" }));
    // the button says it is still at work
    expect(
      within(file).getByRole("button", { name: "Resealing…" }),
    ).toBeVisible();
    expect(await screen.findByText("Resealed 1 Value")).toBeVisible();
    await waitFor(() =>
      expect(
        within(file).getByRole("button", { name: "Reseal All" }),
      ).toBeVisible(),
    );
  });

  it("is grayed out, with why, when it can't be used", async () => {
    // no write access
    renderAt(
      "/dev/secrets/example-org/platform",
      fakeApi({
        me: ADMIN,
        files: {
          "example-org/platform": billing({ repository: REPO_PLATFORM }),
        },
      }),
    );
    expect(
      availability(
        within(await panel()).getByRole("button", { name: /Reseal All/ }),
      ),
    ).toBe("Resealing needs write access to this repository on GitHub.");
  });

  it("is grayed out while the env can't reseal", async () => {
    renderAt(
      PAGE,
      fakeApi({
        me: ADMIN,
        files: { "example-org/apps": billing() },
        status: {
          ...STATUS,
          can_reseal: false,
          reseal_blocked:
            "no agent with the reseal capability holds the env key",
        },
      }),
    );
    const file = await panel();
    await waitFor(() =>
      expect(
        availability(within(file).getByRole("button", { name: /Reseal All/ })),
      ).toBe("No agent with the reseal capability holds the env key."),
    );
    // a tap shows why, and does nothing else
    fireEvent.click(within(file).getByRole("button", { name: /Reseal All/ }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("is grayed out for a file with no sealed values", async () => {
    renderAt(
      PAGE,
      fakeApi({
        me: ADMIN,
        files: {
          "example-org/apps": billing({
            files: [
              {
                ...listing().files[0]!,
                documents: listing().files[0]!.documents!.map((d) => ({
                  ...d,
                  keys: [],
                })),
              },
            ],
          }),
        },
      }),
    );
    const file = await panel();
    const button = () =>
      within(file).getByRole("button", { name: /Reseal All/ });
    await waitFor(() =>
      expect(availability(button())).toBe(
        "This file has no sealed values for the dev env.",
      ),
    );
  });

  it("is grayed out while a seal is running", async () => {
    renderAt(
      PAGE,
      fakeApi({
        me: ADMIN,
        files: { "example-org/apps": billing() },
        sealStatuses: ["sealing"],
      }),
    );
    const file = await panel();
    const form = within(file).getByRole("form", {
      name: `Seal a value into ${BILLING}`,
    });
    fireEvent.change(within(form).getByLabelText("Key"), {
      target: { value: "token" },
    });
    fireEvent.change(within(form).getByLabelText("Value"), {
      target: { value: "s3cr3t" },
    });
    fireEvent.click(within(form).getByRole("button", { name: "Seal" }));
    await waitFor(() =>
      expect(
        availability(within(file).getByRole("button", { name: /Reseal All/ })),
      ).toBe("Wait for the seal in progress to finish."),
    );
  });

  it("is not offered to people who are not admins", async () => {
    renderAt(
      PAGE,
      fakeApi({ me: ME, files: { "example-org/apps": billing() } }),
    );
    const file = await screen.findByRole("region", { name: BILLING });
    await within(file).findByRole("form");
    expect(
      within(file).queryByRole("button", { name: /Reseal All/ }),
    ).not.toBeInTheDocument();
  });
});

/** Answers the nth GET of a file reseal's progress with `fail` instead. */
function failingPoll(
  api: FakeApi,
  nth: number,
  fail: (config: Parameters<AxiosAdapter>[0]) => Error,
): AxiosAdapter {
  let polls = 0;
  return async (config) => {
    if (
      (config.method ?? "get").toLowerCase() === "get" &&
      /\/reseals\/[^/]+$/.test(config.url ?? "")
    ) {
      polls++;
      if (polls === nth) throw fail(config);
    }
    return api.adapter(config);
  };
}

/** An error response from the control plane, as axios raises it. */
function httpError(
  config: Parameters<AxiosAdapter>[0],
  status: number,
  error: string,
  headers: Record<string, string> = {},
): AxiosError {
  return new AxiosError("error", "ERR_BAD_RESPONSE", config, undefined, {
    status,
    statusText: "",
    data: { error },
    headers,
    config,
  } as never);
}

/** Starts "Reseal All" on the billing file. */
async function startReseal() {
  const file = await panel();
  fireEvent.click(within(file).getByRole("button", { name: /Reseal All/ }));
  fireEvent.click(
    within(await screen.findByRole("dialog")).getByRole("button", {
      name: "Reseal All",
    }),
  );
  return file;
}

describe("Reseal all, when something goes wrong", () => {
  const originalAdapter = apiClient.defaults.adapter;
  beforeEach(() => {
    sealPolling.intervalMs = 5;
    resealPolling.intervalMs = 5;
    resealPolling.maxBackoffMs = 20;
  });
  afterEach(() => {
    apiClient.defaults.adapter = originalAdapter;
  });

  const reseals = (api: FakeApi) =>
    api.calls.filter((c) => c.method === "POST" && c.url.endsWith("/reseals"));

  it("keeps following a reseal through a failed check, and never asks again", async () => {
    const api = fakeApi({
      me: ADMIN,
      files: { "example-org/apps": billing() },
      sessions: { "example-org/apps": { ...SESSION, changes: [] } },
      fileReseals: [
        fileReseal({ status: "resealing" }),
        fileReseal({ status: "resealing" }),
        fileReseal({ status: "done" }),
      ],
    });
    // the second check is lost on the way, as on a flaky network
    renderAt(PAGE, {
      adapter: failingPoll(
        api,
        2,
        (config) => new AxiosError("Network Error", "ERR_NETWORK", config),
      ),
    });
    await startReseal();
    expect(
      await screen.findByRole("dialog", { name: "Resealed 1 Value" }),
    ).toBeVisible();
    expect(reseals(api)).toHaveLength(1);
  });

  it("says it is trying again while checks fail, and waits as a 429 asks", async () => {
    const api = fakeApi({
      me: ADMIN,
      files: { "example-org/apps": billing() },
      sessions: { "example-org/apps": { ...SESSION, changes: [] } },
      fileReseals: [
        fileReseal({ status: "resealing" }),
        fileReseal({ status: "done" }),
      ],
    });
    resealPolling.maxBackoffMs = 60_000;
    let polls = 0;
    const started = Date.now();
    let retried = 0;
    renderAt(PAGE, {
      adapter: async (config) => {
        if (/\/reseals\/[^/]+$/.test(config.url ?? "")) {
          polls++;
          if (polls === 1) {
            throw httpError(config, 429, "too many requests", {
              "retry-after": "1",
            });
          }
          if (polls === 2) retried = Date.now() - started;
        }
        return api.adapter(config);
      },
    });
    await startReseal();
    const running = await screen.findByRole("dialog", { name: "Resealing…" });
    expect(
      await within(running).findByText(
        /Couldn't check its progress: Too many requests.*Trying again/,
      ),
    ).toBeVisible();
    await screen.findByRole(
      "dialog",
      { name: "Resealed 1 Value" },
      {
        timeout: 3000,
      },
    );
    // a second later, as Retry-After said, not 5ms
    expect(retried).toBeGreaterThanOrEqual(900);
    expect(reseals(api)).toHaveLength(1);
  });

  it("stops following when it may not, and says the changes may still come", async () => {
    const api = fakeApi({
      me: ADMIN,
      files: { "example-org/apps": billing() },
      sessions: { "example-org/apps": { ...SESSION, changes: [] } },
      fileReseals: [fileReseal({ status: "resealing" })],
    });
    renderAt(PAGE, {
      adapter: failingPoll(api, 2, (config) =>
        httpError(config, 403, "you need write access to example-org/apps"),
      ),
    });
    await startReseal();
    const ask = await screen.findByRole("dialog", {
      name: "Reseal All Values in This File?",
    });
    expect(within(ask).getByRole("alert")).toHaveTextContent(
      "Lost track of the reseal: You need write access to example-org/apps. If it finishes, its changes join your pending changes.",
    );
    expect(reseals(api)).toHaveLength(1);
  });

  it("says when the session ended, and starts a new one when tried again", async () => {
    const api = fakeApi({
      me: ADMIN,
      files: { "example-org/apps": billing() },
      sessions: { "example-org/apps": { ...SESSION, changes: [] } },
      fileReseals: [fileReseal({ status: "resealing" })],
      // it expires as the reseal runs
      endSessionAfterResealPolls: 1,
    });
    renderAt(PAGE, api);
    await startReseal();
    const ask = await screen.findByRole("dialog", {
      name: "Reseal All Values in This File?",
    });
    expect(await within(ask).findByRole("alert")).toHaveTextContent(
      "Your session ended: it expired, or its changes were discarded or sent in a pull request. Reseal the file again to start a new one.",
    );
    // the workspace takes the session as gone
    expect(
      screen.getByRole("region", { name: /pending changes/i, hidden: true }),
    ).toHaveTextContent(/Nothing sealed yet/);
    fireEvent.click(within(ask).getByRole("button", { name: "Reseal All" }));
    await waitFor(() => expect(reseals(api)).toHaveLength(2));
    expect(
      api.calls.filter((c) => c.method === "POST").map((c) => c.url),
    ).toEqual([
      `${APPS}/session/${SESSION.id}/reseals`,
      `${APPS}/session`,
      `${APPS}/session/${SESSION.id}/reseals`,
    ]);
  });

  it("holds the pull request back until the reseal finishes, and says why", async () => {
    const api = fakeApi({
      me: ADMIN,
      files: { "example-org/apps": billing() },
      sessions: {
        "example-org/apps": {
          ...SESSION,
          pending_changes: 1,
          changes: [SEALED],
        },
      },
      fileReseals: [fileReseal({ status: "resealing" })],
    });
    renderAt(PAGE, api);
    await startReseal();
    const running = await screen.findByRole("dialog", { name: "Resealing…" });
    fireEvent.click(within(running).getByText("Close", { selector: "button" }));
    const pending = screen.getByRole("region", { name: /pending changes/i });
    const open = within(pending).getByRole("button", {
      name: "Open Pull Request",
    });
    expect(open).toBeDisabled();
    expect(open).toHaveAccessibleDescription(
      "Wait for the reseal in progress to finish.",
    );
  });

  it("keeps a repository's reseal to that repository", async () => {
    const api = fakeApi({
      me: ADMIN,
      files: {
        "example-org/apps": billing(),
        "example-org/platform": billing({
          repository: { ...REPO_PLATFORM, access: "write" },
        }),
      },
      sessions: { "example-org/apps": { ...SESSION, changes: [] } },
      fileReseals: [fileReseal({ status: "resealing" })],
    });
    const router = renderAt(PAGE, api);
    await startReseal();
    fireEvent.click(
      within(
        await screen.findByRole("dialog", { name: "Resealing…" }),
      ).getByText("Close", { selector: "button" }),
    );
    await act(async () => {
      await router.navigate({
        to: "/$env/secrets/$owner/$repo",
        params: { env: "dev", owner: "example-org", repo: "platform" },
      });
    });
    await screen.findByRole("heading", {
      level: 1,
      name: "example-org/platform",
    });
    // the other repository's file at the same path is not resealing
    const file = await panel();
    expect(
      within(file).getByRole("button", { name: "Reseal All" }),
    ).toBeVisible();
    expect(
      within(file).queryByRole("button", { name: /Resealing/ }),
    ).not.toBeInTheDocument();
  });

  it("says when the status can't be read, rather than checking for good", async () => {
    const api = fakeApi({
      me: ADMIN,
      files: { "example-org/apps": billing() },
    });
    renderAt(PAGE, {
      adapter: async (config) => {
        if ((config.url ?? "").endsWith("/status")) {
          throw httpError(config, 503, "the control plane is starting");
        }
        return api.adapter(config);
      },
    });
    const file = await panel();
    await waitFor(() =>
      expect(
        availability(within(file).getByRole("button", { name: /Reseal All/ })),
      ).toBe(
        "Couldn't check whether values can be resealed: The control plane is starting. Trying again.",
      ),
    );
  });
});

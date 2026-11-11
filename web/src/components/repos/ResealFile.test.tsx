import { describe, it, expect, afterEach, beforeEach } from "vitest";
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
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

function renderAt(path: string, api: FakeApi) {
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

/** The billing file's panel, once its "Reseal all" is there. */
async function panel() {
  const region = await screen.findByRole("region", { name: BILLING });
  await within(region).findByRole("button", { name: /Reseal all/ });
  return region;
}

/** "enabled", or the reason a grayed-out button gives. */
function availability(button: HTMLElement): string {
  if (button.getAttribute("aria-disabled") !== "true") return "enabled";
  const id = (button.getAttribute("aria-describedby") ?? "").split(" ")[0]!;
  return document.getElementById(id)?.textContent ?? "no reason";
}

describe("Reseal all", () => {
  const originalAdapter = apiClient.defaults.adapter;
  beforeEach(() => {
    sealPolling.intervalMs = 5;
    resealPolling.intervalMs = 5;
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
    const button = within(file).getByRole("button", { name: /Reseal all/ });
    expect(availability(button)).toBe("enabled");
    fireEvent.click(button);

    // what it does and doesn't do, before it starts
    const ask = await screen.findByRole("dialog", {
      name: "Reseal all values in this file?",
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
    fireEvent.click(within(ask).getByRole("button", { name: "Reseal all" }));

    // its progress, then what it did
    const progress = await screen.findByRole("progressbar", {
      name: "Values checked",
    });
    expect(progress).toHaveAttribute("aria-valuemax", "2");
    await screen.findByText("Resealing in dev-use1-blue: 1 of 2 values…");
    const done = await screen.findByRole("dialog", {
      name: "Resealed 1 value",
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
    // and the pull request says what it writes
    fireEvent.click(
      within(pending).getByRole("button", { name: "Open pull request" }),
    );
    expect(
      await screen.findByRole("dialog", { name: "Open a pull request?" }),
    ).toHaveTextContent(
      "writes 1 sealed value and 1 resealed value into 1 file",
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
      within(await panel()).getByRole("button", { name: /Reseal all/ }),
    );
    const ask = await screen.findByRole("dialog");
    expect(ask).toHaveTextContent(
      "Values with a pending change in your session are left alone.",
    );
    fireEvent.click(within(ask).getByRole("button", { name: "Reseal all" }));
    await screen.findByRole("dialog", { name: "Resealed 1 value" });
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
      within(await panel()).getByRole("button", { name: /Reseal all/ }),
    );
    fireEvent.click(
      within(await screen.findByRole("dialog")).getByRole("button", {
        name: "Reseal all",
      }),
    );
    const done = await screen.findByRole("dialog", {
      name: "No value was resealed",
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
      within(await panel()).getByRole("button", { name: /Reseal all/ }),
    );
    fireEvent.click(
      within(await screen.findByRole("dialog")).getByRole("button", {
        name: "Reseal all",
      }),
    );
    const done = await screen.findByRole("dialog", {
      name: "Resealing timed out",
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
      within(await panel()).getByRole("button", { name: /Reseal all/ }),
    );
    const ask = await screen.findByRole("dialog");
    fireEvent.click(within(ask).getByRole("button", { name: "Reseal all" }));
    expect(await within(ask).findByRole("alert")).toHaveTextContent(
      "Could not reseal the file: 3 keys need resealing, and the session takes 50 changes: remove some first.",
    );
    expect(
      within(ask).getByRole("button", { name: "Reseal all" }),
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
    fireEvent.click(within(file).getByRole("button", { name: /Reseal all/ }));
    fireEvent.click(
      within(await screen.findByRole("dialog")).getByRole("button", {
        name: "Reseal all",
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
    expect(await screen.findByText("Resealed 1 value")).toBeVisible();
    await waitFor(() =>
      expect(
        within(file).getByRole("button", { name: "Reseal all" }),
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
        within(await panel()).getByRole("button", { name: /Reseal all/ }),
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
        availability(within(file).getByRole("button", { name: /Reseal all/ })),
      ).toBe("No agent with the reseal capability holds the env key."),
    );
    // a tap shows why, and does nothing else
    fireEvent.click(within(file).getByRole("button", { name: /Reseal all/ }));
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
      within(file).getByRole("button", { name: /Reseal all/ });
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
        availability(within(file).getByRole("button", { name: /Reseal all/ })),
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
      within(file).queryByRole("button", { name: /Reseal all/ }),
    ).not.toBeInTheDocument();
  });
});

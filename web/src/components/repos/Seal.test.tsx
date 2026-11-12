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
import { ThemeProvider } from "@/lib/theme-provider";
import { routeTree } from "@/routeTree.gen";
import {
  ME,
  REPO_APPS,
  REPO_PLATFORM,
  SEAL,
  SESSION,
  changeFor,
  fakeApi,
  listing,
  type FakeApi,
} from "@/test/fake-api";
import { sealPolling } from "./SealForm";

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

/** The apps repository's page, and its API path. */
const PAGE = "/secrets/example-org/apps";
const APPS = "/repos/example-org/apps";
const BILLING = "deploy/billing/sealed-secret.yaml";

/** The seal form of the selected file, the billing file by default. */
async function openForm(path = BILLING) {
  const panel = await screen.findByRole("region", { name: path });
  const form = within(panel).getByRole("form", {
    name: `Seal a value into ${path}`,
  });
  return {
    form,
    key: within(form).getByLabelText("Key"),
    value: within(form).getByLabelText("Value"),
    seal: within(form).getByRole("button", { name: "Seal" }),
  };
}

describe("sealing", () => {
  const originalAdapter = apiClient.defaults.adapter;
  beforeEach(() => {
    sealPolling.intervalMs = 5;
  });
  afterEach(() => {
    apiClient.defaults.adapter = originalAdapter;
  });

  it("seals a value into every document of a file and lists the change", async () => {
    const api = fakeApi({ me: ME, files: { "example-org/apps": listing() } });
    renderAt(PAGE, api);

    const { form, key, value, seal } = await openForm();
    expect(within(form).getByText(/each of the 2 documents/)).toBeVisible();
    expect(seal).toBeDisabled();
    // before the first seal, the pending changes say what will gather there
    expect(
      screen.getByRole("region", { name: /pending changes/i }),
    ).toHaveTextContent(/Nothing sealed yet/);
    // Enter in the key moves to the value; Ctrl/⌘+Enter seals
    fireEvent.change(key, { target: { value: "api-token" } });
    fireEvent.keyDown(key, { key: "Enter" });
    expect(value).toHaveFocus();
    fireEvent.change(value, { target: { value: "s3cr3t" } });
    fireEvent.keyDown(value, { key: "Enter", ctrlKey: true });

    const done = await within(form).findByText(/sealed/i, { selector: "span" });
    expect(done).toHaveTextContent(
      /Sealed api-token for 2 documents by dev-use1-blue/,
    );
    // ready for the next value, with a notice that names no value
    expect(done.closest("[role=status]")).not.toHaveTextContent("s3cr3t");
    expect(value).toHaveValue("");
    expect(key).toHaveValue("");
    expect(key).toHaveFocus();

    // the session opened at the commit on screen; both writes carry the
    // CSRF token, and the value went out once, to the seal request
    const writes = api.calls.filter((c) => c.method !== "GET");
    expect(writes.map((c) => [c.method, c.url, c.csrf])).toEqual([
      ["POST", `${APPS}/session`, ME.csrf_token],
      ["POST", `${APPS}/session/${SESSION.id}/seals`, ME.csrf_token],
    ]);
    expect(writes[0]?.body).toEqual({ commit: listing().commit });
    expect(writes[1]?.body).toEqual({
      path: BILLING,
      key: "api-token",
      value: "s3cr3t",
    });
    expect(
      api.calls.filter((c) => JSON.stringify(c.body ?? "").includes("s3cr3t")),
    ).toHaveLength(1);
    // the browser remembers the repository and file for the Secrets page,
    // and never the value or the key
    const remembered = localStorage.getItem("sealer.recent-repos:octocat:dev");
    expect(JSON.parse(remembered ?? "[]")).toEqual([
      {
        repository: "example-org/apps",
        path: BILLING,
        sealed_at: expect.any(String),
      },
    ]);
    expect(remembered).not.toContain("s3cr3t");
    expect(remembered).not.toContain("api-token");

    // the pending change appears beside the files, and the file marks the
    // key as new
    const pending = await screen.findByRole("region", {
      name: /pending changes/i,
    });
    const item = within(
      (await within(pending).findByText("api-token")).closest(
        "li",
      ) as HTMLElement,
    );
    expect(item.getByRole("button", { name: BILLING })).toBeInTheDocument();
    expect(item.getByText("2 documents")).toBeInTheDocument();
    expect(item.getByTitle(/^Sealed by dev-use1-blue with/)).toBeVisible();
    const keys = within(
      screen.getByRole("region", { name: BILLING }),
    ).getByRole("list", { name: "Keys" });
    const row = within(keys).getByRole("button", { name: /^api-token/ });
    expect(row).toHaveTextContent("api-tokenNew, in your pending changes");
    // "Seal Again" is only for values sealed with a revoked key
    expect(row).toHaveTextContent(/Replace$/);
    const files = screen.getByRole("list", { name: "Files" });
    expect(
      within(files).getByRole("button", { name: /billing.*1 pending change/ }),
    ).toBeInTheDocument();
  });

  it("keeps the value when a seal fails, and says why", async () => {
    renderAt(
      PAGE,
      fakeApi({
        me: ME,
        files: { "example-org/apps": listing() },
        sessions: { "example-org/apps": SESSION },
        sealStatuses: ["sealing", "failed"],
        sealError: "refusing to seal: key is not in this cluster's key set",
      }),
    );
    const { form, key, value, seal } = await openForm();
    fireEvent.change(key, { target: { value: "api-token" } });
    fireEvent.change(value, { target: { value: "s3cr3t" } });
    fireEvent.click(seal);
    expect(await within(form).findByRole("alert")).toHaveTextContent(
      "Not sealed: refusing to seal: key is not in this cluster's key set",
    );
    expect(value).toHaveValue("s3cr3t");
    expect(seal).toBeEnabled();
  });

  it("checks the key, and notes when it replaces one", async () => {
    renderAt(
      PAGE,
      fakeApi({ me: ME, files: { "example-org/apps": listing() } }),
    );
    const { form, key, value, seal } = await openForm();
    fireEvent.change(value, { target: { value: "v" } });
    fireEvent.change(key, { target: { value: "a/b" } });
    expect(within(form).getByText(/letters, digits/)).toBeVisible();
    expect(key).toHaveAttribute("aria-invalid", "true");
    expect(seal).toBeDisabled();
    fireEvent.change(key, { target: { value: "api-key" } });
    // one document holds it, the other doesn't
    expect(key).toHaveAccessibleDescription(
      "Replaces api-key where it is set and adds it to the other documents.",
    );
    expect(seal).toBeEnabled();
    fireEvent.change(key, { target: { value: "new-key" } });
    expect(key).toHaveAccessibleDescription(
      "Adds new-key to spec.encryptedData.",
    );
    // keys and fields in the note are monospace
    expect(
      within(form).getByText("new-key", { selector: "code" }),
    ).toBeVisible();
    // existing keys are suggested
    const options = Array.from(
      document.querySelectorAll(
        `#${CSS.escape(key.getAttribute("list") ?? "")} option`,
      ),
    ).map((o) => o.getAttribute("value"));
    expect(options).toEqual(["api-key"]);
    // the value is masked until shown
    expect(value.className).toContain("[-webkit-text-security:disc]");
    fireEvent.click(
      within(form).getByRole("button", { name: "Show the value" }),
    );
    expect(value.className).not.toContain("[-webkit-text-security:disc]");
  });

  it("removes a change, and discards the session after confirming", async () => {
    const api = fakeApi({
      me: ME,
      files: { "example-org/apps": listing() },
      sessions: {
        "example-org/apps": {
          ...SESSION,
          pending_changes: 2,
          changes: [changeFor(SEAL), changeFor({ ...SEAL, key: "password" })],
        },
      },
    });
    renderAt(PAGE, api);
    const pending = await screen.findByRole("region", {
      name: /pending changes/i,
    });
    const changes = within(pending).getByRole("list", {
      name: "Pending changes",
    });
    expect(within(changes).getAllByRole("listitem")).toHaveLength(2);
    // the files are read at the session's commit
    expect(api.calls.find((c) => c.url === `${APPS}/files`)?.params).toEqual({
      commit: SESSION.commit,
    });

    fireEvent.click(
      within(pending).getByRole("button", {
        name: `Remove password from ${BILLING}`,
      }),
    );
    await within(pending).findByText("1", { selector: "span" });
    expect(within(changes).getAllByRole("listitem")).toHaveLength(1);
    // a toast says what went, the key in monospace
    const toast = await screen.findByText(/^Removed/);
    expect(within(toast).getByText("password")).toHaveClass("font-mono");

    fireEvent.click(within(pending).getByRole("button", { name: "Discard" }));
    const dialog = await screen.findByRole("dialog", {
      name: "Discard Pending Changes?",
    });
    expect(dialog).toHaveTextContent("This removes 1 pending change");
    fireEvent.click(within(dialog).getByRole("button", { name: "Discard" }));
    // the card stays, saying what will gather in it
    expect(await screen.findByText(/Nothing sealed yet/)).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Open Pull Request" }),
    ).not.toBeInTheDocument();
    expect(
      api.calls.filter((c) => c.method === "DELETE").map((c) => c.url),
    ).toEqual([
      `${APPS}/session/${SESSION.id}/changes/${changeFor({ ...SEAL, key: "password" }).id}`,
      `${APPS}/session/${SESSION.id}`,
    ]);
  });

  it("keeps pending changes reachable when their commit can't be read", async () => {
    // no files: the listing at the session's commit is not found
    const api = fakeApi({
      me: ME,
      sessions: {
        "example-org/apps": {
          ...SESSION,
          pending_changes: 1,
          changes: [changeFor(SEAL)],
        },
      },
    });
    renderAt(PAGE, api);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /Could Not Load This Repository.*If it is gone from main, discard the changes/,
    );
    const pending = screen.getByRole("region", { name: /pending changes/i });
    fireEvent.click(within(pending).getByRole("button", { name: "Discard" }));
    const dialog = await screen.findByRole("dialog", {
      name: "Discard Pending Changes?",
    });
    fireEvent.click(within(dialog).getByRole("button", { name: "Discard" }));
    await waitFor(() =>
      expect(
        api.calls.filter((c) => c.method === "DELETE").map((c) => c.url),
      ).toEqual([`${APPS}/session/${SESSION.id}`]),
    );
  });

  it("offers no sealing to read-only users", async () => {
    renderAt(
      "/secrets/example-org/platform",
      fakeApi({
        me: ME,
        files: {
          "example-org/platform": listing({ repository: REPO_PLATFORM }),
        },
      }),
    );
    await screen.findByRole("region", { name: BILLING });
    expect(screen.queryByRole("form")).not.toBeInTheDocument();
    expect(screen.getByText(/not write to it/)).toBeInTheDocument();
    // the keys show, but picking one fills nothing
    const keys = screen.getByRole("list", { name: "Keys" });
    expect(within(keys).getByText("api-key")).toBeInTheDocument();
    expect(within(keys).queryByRole("button")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("region", { name: /pending changes/i }),
    ).not.toBeInTheDocument();
  });

  it("marks repositories with pending changes", async () => {
    renderAt(
      "/secrets",
      fakeApi({
        me: ME,
        repos: [REPO_APPS, REPO_PLATFORM],
        sessions: {
          "example-org/apps": { ...SESSION, pending_changes: 2 },
        },
      }),
    );
    const apps = await screen.findByRole("rowheader", {
      name: /example-org\/apps/,
    });
    expect(
      await within(apps).findByText("2 Pending Changes"),
    ).toBeInTheDocument();
  });

  it("opens a pull request with the pending changes, then links to it", async () => {
    const api = fakeApi({
      me: ME,
      files: { "example-org/apps": listing() },
      sessions: {
        "example-org/apps": {
          ...SESSION,
          pending_changes: 3,
          changes: [
            changeFor(SEAL),
            changeFor({ ...SEAL, key: "password" }),
            changeFor({ ...SEAL, path: "deploy/search/sealed-secret.yaml" }),
          ],
        },
      },
    });
    renderAt(PAGE, api);
    const pending = await screen.findByRole("region", {
      name: /pending changes/i,
    });
    fireEvent.click(
      within(pending).getByRole("button", { name: "Open Pull Request" }),
    );
    const dialog = await screen.findByRole("dialog", {
      name: "Open a Pull Request?",
    });
    expect(dialog).toHaveTextContent(
      "writes 3 sealed values into 2 files, changing only spec.encryptedData",
    );
    const files = within(dialog).getByRole("list", {
      name: "Files in the pull request",
    });
    expect(within(files).getAllByRole("listitem")).toHaveLength(2);
    expect(files).toHaveTextContent(`${BILLING}api-tokenpassword`);

    fireEvent.click(
      within(dialog).getByRole("button", { name: "Open Pull Request" }),
    );
    // a dialog says it is open, with the way to it
    const opened = await screen.findByRole("dialog", {
      name: "Pull Request #7 Is Open",
    });
    const link = within(opened).getByRole("link", {
      name: /view pull request/i,
    });
    expect(link).toHaveAttribute(
      "href",
      "https://github.com/example-org/apps/pull/7",
    );
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    fireEvent.click(
      within(opened).getByRole("button", { name: "Keep Sealing" }),
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    // and a banner keeps the link
    const banner = screen.getByRole("status", { name: "Pull request opened" });
    expect(banner).toHaveTextContent("Opened pull request #7");
    expect(
      within(banner).getByRole("link", { name: /view pull request/i }),
    ).toHaveAttribute("href", "https://github.com/example-org/apps/pull/7");
    // the session ended with it
    expect(await screen.findByText(/Nothing sealed yet/)).toBeInTheDocument();
    const call = api.calls.find((c) => c.url.endsWith("/pull-request"));
    expect(call).toMatchObject({
      method: "POST",
      url: `${APPS}/session/${SESSION.id}/pull-request`,
      csrf: ME.csrf_token,
    });

    fireEvent.click(within(banner).getByRole("button", { name: "Dismiss" }));
    expect(banner).not.toBeInTheDocument();
  });

  it("keeps the changes and says why when a pull request is refused", async () => {
    const api = fakeApi({
      me: ME,
      files: { "example-org/apps": listing() },
      sessions: {
        "example-org/apps": {
          ...SESSION,
          pending_changes: 1,
          changes: [changeFor(SEAL)],
        },
      },
      pullRequestError: {
        status: 422,
        error: `${BILLING}: its documents for the dev env no longer match what api-token was sealed for; seal it again`,
      },
    });
    renderAt(PAGE, api);
    const pending = await screen.findByRole("region", {
      name: /pending changes/i,
    });
    fireEvent.click(
      within(pending).getByRole("button", { name: "Open Pull Request" }),
    );
    const dialog = await screen.findByRole("dialog", {
      name: "Open a Pull Request?",
    });
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Open Pull Request" }),
    );
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "Could not open the pull request: deploy/billing/sealed-secret.yaml: its documents for the dev env no longer match what api-token was sealed for; seal it again",
    );
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(
      screen.getByRole("region", { name: /pending changes/i }),
    ).toHaveTextContent("api-token");
  });

  it("shows no pull request footer for a session without changes", async () => {
    renderAt(
      PAGE,
      fakeApi({
        me: ME,
        files: { "example-org/apps": listing() },
        sessions: { "example-org/apps": { ...SESSION } },
      }),
    );
    const pending = await screen.findByRole("region", {
      name: /pending changes/i,
    });
    expect(pending).toHaveTextContent(/Nothing sealed yet/);
    expect(
      within(pending).queryByRole("button", { name: "Open Pull Request" }),
    ).not.toBeInTheDocument();
    expect(
      within(pending).queryByRole("button", { name: "Discard" }),
    ).not.toBeInTheDocument();
  });

  it("offers no pull request while a seal is running, and says why under the button", async () => {
    sealPolling.intervalMs = 60;
    const api = fakeApi({
      me: ME,
      files: { "example-org/apps": listing() },
      sessions: {
        "example-org/apps": {
          ...SESSION,
          pending_changes: 1,
          changes: [changeFor({ ...SEAL, key: "password" })],
        },
      },
      sealStatuses: ["queued", "sealing", "sealing", "sealing", "sealed"],
    });
    renderAt(PAGE, api);
    const pending = await screen.findByRole("region", {
      name: /pending changes/i,
    });
    const open = within(pending).getByRole("button", {
      name: "Open Pull Request",
    });
    expect(open).toBeEnabled();

    const { key, value, seal } = await openForm();
    fireEvent.change(key, { target: { value: "api-token" } });
    fireEvent.change(value, { target: { value: "s3cr3t" } });
    fireEvent.click(seal);
    const why = "Wait for the seal in progress to finish.";
    await waitFor(() => expect(open).toHaveAttribute("title", why));
    expect(open).toBeDisabled();
    // the reason is on screen, not only in the title
    expect(within(pending).getByText(why)).toBeVisible();
    expect(open).toHaveAccessibleDescription(why);
    // nor can a key be picked while it runs
    const keys = screen.getByRole("list", { name: "Keys" });
    expect(
      within(keys).getByRole("button", { name: /^api-key/ }),
    ).toBeDisabled();
    await waitFor(() => expect(open).toBeEnabled(), { timeout: 3000 });
    expect(within(pending).queryByText(why)).not.toBeInTheDocument();
  });

  it("clears a seal's status once its change is removed", async () => {
    const api = fakeApi({
      me: ME,
      files: { "example-org/apps": listing() },
      sessions: { "example-org/apps": { ...SESSION } },
    });
    renderAt(PAGE, api);
    const { form, key, value, seal } = await openForm();
    fireEvent.change(key, { target: { value: "api-token" } });
    fireEvent.change(value, { target: { value: "s3cr3t" } });
    fireEvent.click(seal);
    await within(form).findByText(/sealed/i, { selector: "span" });
    const pending = screen.getByRole("region", { name: /pending changes/i });
    await within(pending).findByText("api-token");
    // the status stays while its change waits
    expect(
      within(form).getByText(/sealed/i, { selector: "span" }),
    ).toBeVisible();

    fireEvent.click(
      within(pending).getByRole("button", {
        name: `Remove api-token from ${BILLING}`,
      }),
    );
    await waitFor(() =>
      expect(
        within(form).queryByText(/sealed/i, { selector: "span" }),
      ).not.toBeInTheDocument(),
    );
  });

  it("clears a seal's status once the changes are discarded", async () => {
    const api = fakeApi({
      me: ME,
      files: { "example-org/apps": listing() },
      sessions: { "example-org/apps": { ...SESSION } },
    });
    renderAt(PAGE, api);
    const { form, key, value, seal } = await openForm();
    fireEvent.change(key, { target: { value: "api-token" } });
    fireEvent.change(value, { target: { value: "s3cr3t" } });
    fireEvent.click(seal);
    await within(form).findByText(/sealed/i, { selector: "span" });
    const pending = screen.getByRole("region", { name: /pending changes/i });
    await within(pending).findByText("api-token");

    fireEvent.click(within(pending).getByRole("button", { name: "Discard" }));
    const dialog = await screen.findByRole("dialog", {
      name: "Discard Pending Changes?",
    });
    fireEvent.click(within(dialog).getByRole("button", { name: "Discard" }));
    await waitFor(() =>
      expect(
        within(form).queryByText(/sealed/i, { selector: "span" }),
      ).not.toBeInTheDocument(),
    );
  });

  it("asks for a value sealed with a revoked key to be sealed again", async () => {
    const revoked = { ...changeFor(SEAL), key_revoked: true };
    const api = fakeApi({
      me: ME,
      files: { "example-org/apps": listing() },
      sessions: {
        "example-org/apps": {
          ...SESSION,
          pending_changes: 1,
          changes: [revoked],
        },
      },
    });
    renderAt(PAGE, api);
    const pending = await screen.findByRole("region", {
      name: /pending changes/i,
    });
    const badge = within(pending).getByText("Seal Again");
    expect(badge).toHaveAttribute("title", expect.stringMatching(/revoked/));
    const open = within(pending).getByRole("button", {
      name: "Open Pull Request",
    });
    expect(open).toBeDisabled();
    const why = "Seal again, or remove, the values sealed with a revoked key.";
    expect(open).toHaveAttribute("title", why);
    expect(within(pending).getByText(why)).toBeVisible();

    // the key row, its region chips and the file say so too, in amber, not
    // as a pending value
    const panel = screen.getByRole("region", { name: BILLING });
    const keys = within(panel).getByRole("list", { name: "Keys" });
    const row = within(keys).getByRole("button", { name: /^api-token/ });
    expect(row).toHaveTextContent("Sealed with a revoked key; seal it again");
    expect(row).toHaveTextContent(/Seal Again$/);
    expect(
      within(keys).getByRole("button", {
        name: "use2: sealed with a revoked key, seal again. Seal api-token for use2 only",
      }),
    ).toHaveClass("text-warning");
    const files = screen.getByRole("list", { name: "Files" });
    const billing = within(files).getByRole("button", { name: /billing/ });
    expect(within(billing).getByText("Seal Again")).toBeInTheDocument();
    // and not as a blue pending count
    expect(within(billing).queryByText("pending")).not.toBeInTheDocument();
  });

  it("jumps to a file from the file list or a pending change", async () => {
    renderAt(
      PAGE,
      fakeApi({
        me: ME,
        files: { "example-org/apps": listing() },
        sessions: {
          "example-org/apps": {
            ...SESSION,
            pending_changes: 1,
            changes: [changeFor(SEAL)],
          },
        },
      }),
    );
    const files = await screen.findByRole("list", { name: "Files" });
    const billing = within(files).getByRole("button", { name: /billing/ });
    expect(billing).toHaveAttribute("aria-current", "true");

    // the filter narrows the list; Enter opens the first match
    const filter = screen.getByRole("searchbox", { name: "Filter files" });
    fireEvent.keyDown(document.body, { key: "/" });
    expect(filter).toHaveFocus();
    fireEvent.change(filter, { target: { value: "legacy" } });
    expect(within(files).getAllByRole("button")).toHaveLength(1);
    fireEvent.keyDown(filter, { key: "Enter" });
    const legacy = await screen.findByRole("region", {
      name: "deploy/legacy/sealed-secret.yaml",
    });
    // the server's problem, as a sentence; a refused scope is a warning
    expect(legacy).toHaveTextContent("Cluster-wide scope is not allowed.");
    expect(within(legacy).getByText("Cluster-Wide")).toHaveClass(
      "text-warning",
    );
    expect(legacy).toHaveTextContent(/can't be sealed into/);
    expect(within(legacy).queryByRole("form")).not.toBeInTheDocument();
    // nothing can be sealed, so there is no empty key list either
    expect(legacy).not.toHaveTextContent(/No keys yet/);

    // a pending change's file opens that file
    const pending = screen.getByRole("region", { name: /pending changes/i });
    fireEvent.click(within(pending).getByRole("button", { name: BILLING }));
    const form = await screen.findByRole("form", {
      name: `Seal a value into ${BILLING}`,
    });
    // a file the user picks is ready to type into
    expect(within(form).getByLabelText("Key")).toHaveFocus();
  });
});

/** The listing, with hints on the billing file's documents. */
function hinted() {
  const base = listing();
  const [billing, ...rest] = base.files;
  return listing({
    files: [
      {
        ...billing!,
        documents: (billing!.documents ?? []).map((d) => ({
          ...d,
          description: "Credentials for the payment provider",
          docs: "https://docs.example.com/runbooks/billing",
          expected_keys: ["api-key", "db-password"],
        })),
      },
      ...rest,
    ],
  });
}

describe("hints", () => {
  const originalAdapter = apiClient.defaults.adapter;
  afterEach(() => {
    apiClient.defaults.adapter = originalAdapter;
  });

  it("shows what a file is for, its docs, and the keys it still lacks", async () => {
    renderAt(
      PAGE,
      fakeApi({ me: ME, files: { "example-org/apps": hinted() } }),
    );

    const panel = await screen.findByRole("region", { name: BILLING });
    expect(
      within(panel).getByText("Credentials for the payment provider"),
    ).toBeVisible();
    const docs = within(panel).getByRole("link", { name: /docs/i });
    expect(docs).toHaveAttribute(
      "href",
      "https://docs.example.com/runbooks/billing",
    );
    expect(docs).toHaveAttribute("rel", "noopener noreferrer");

    // the expected keys come first: api-key is in use2 but not use1,
    // db-password in neither
    const keys = within(panel).getByRole("list", { name: "Keys" });
    expect(
      within(keys).getByRole("button", { name: /^api-key/ }),
    ).toHaveTextContent("api-keyMissing in use1Seal");
    expect(
      within(keys).getByRole("button", { name: /^db-password/ }),
    ).toHaveTextContent("db-passwordExpected, not set yetSeal");
    // and per region, each a way to seal it there only
    const byRegion = (key: string) =>
      within(within(keys).getByRole("list", { name: `${key} by region` }))
        .getAllByRole("button")
        .map((b) => b.getAttribute("aria-label"));
    expect(byRegion("api-key")).toEqual([
      "use1: missing. Seal api-key for use1 only",
      "use2: set. Seal api-key for use2 only",
    ]);
    expect(byRegion("db-password")).toEqual([
      "use1: missing. Seal db-password for use1 only",
      "use2: missing. Seal db-password for use2 only",
    ]);
    expect(within(panel).getByText("2 to seal")).toBeVisible();

    // the file list says so too, and matches on the description
    const files = screen.getByRole("list", { name: "Files" });
    const item = within(files).getByRole("button", { name: /billing/ });
    expect(item).toHaveTextContent("Credentials for the payment provider");
    expect(item).toHaveTextContent("2 Missing");
    fireEvent.change(screen.getByLabelText("Filter files"), {
      target: { value: "payment" },
    });
    expect(within(files).getAllByRole("button")).toHaveLength(1);
  });

  it("fills the form from the key list and warns about unexpected keys", async () => {
    renderAt(
      PAGE,
      fakeApi({ me: ME, files: { "example-org/apps": hinted() } }),
    );
    const { form, key, value } = await openForm();

    const keys = screen.getByRole("list", { name: "Keys" });
    const row = within(keys).getByRole("button", { name: /^db-password/ });
    fireEvent.click(row);
    expect(key).toHaveValue("db-password");
    expect(value).toHaveFocus();
    expect(row).toHaveAttribute("aria-pressed", "true");
    // typing another key moves the mark
    fireEvent.change(key, { target: { value: "api-key" } });
    expect(row).toHaveAttribute("aria-pressed", "false");
    expect(
      within(keys).getByRole("button", { name: /^api-key/ }),
    ).toHaveAttribute("aria-pressed", "true");

    // expected keys are suggested first
    const options = Array.from(
      document.querySelectorAll(
        `#${CSS.escape(key.getAttribute("list") ?? "")} option`,
      ),
    ).map((o) => o.getAttribute("value"));
    expect(options).toEqual(["api-key", "db-password"]);

    fireEvent.change(key, { target: { value: "db-pasword" } });
    const note = within(form).getByText(/does not expect it/);
    expect(note).toHaveClass("text-warning");
    // a warning, not a block
    fireEvent.change(value, { target: { value: "v" } });
    expect(within(form).getByRole("button", { name: "Seal" })).toBeEnabled();
  });
});

describe("regions", () => {
  const originalAdapter = apiClient.defaults.adapter;
  beforeEach(() => {
    sealPolling.intervalMs = 5;
  });
  afterEach(() => {
    apiClient.defaults.adapter = originalAdapter;
  });

  it("seals a value for one region from its chip, and only there", async () => {
    const api = fakeApi({ me: ME, files: { "example-org/apps": hinted() } });
    renderAt(PAGE, api);
    const { form, key, value } = await openForm();
    const panel = screen.getByRole("region", { name: BILLING });

    // db-password is missing in both regions; its use2 chip picks use2
    fireEvent.click(
      screen.getByRole("button", {
        name: "use2: missing. Seal db-password for use2 only",
      }),
    );
    expect(key).toHaveValue("db-password");
    expect(value).toHaveFocus();
    const regions = within(form).getByRole("group", { name: "Regions" });
    expect(
      within(regions).getByRole("button", { name: /use1/ }),
    ).toHaveAttribute("aria-pressed", "false");
    expect(
      within(regions).getByRole("button", { name: /use2/ }),
    ).toHaveAttribute("aria-pressed", "true");
    expect(
      within(form).getByText(/Sealed for the document in use2/),
    ).toBeVisible();
    expect(key).toHaveAccessibleDescription(
      "Adds db-password to spec.encryptedData in use2.",
    );
    // the document left out says so
    expect(
      within(panel).getByText("Sealed for 1 of these 2 documents"),
    ).toBeVisible();
    const use1 = within(panel).getByRole("rowheader", {
      name: /dev-use1-blue-apps\/billing/,
    });
    expect(use1).toHaveTextContent("not in this seal");

    fireEvent.change(value, { target: { value: "s3cr3t" } });
    fireEvent.keyDown(value, { key: "Enter", ctrlKey: true });
    expect(
      await within(form).findByText(/sealed/i, { selector: "span" }),
    ).toHaveTextContent(/Sealed db-password for 1 document in use2 by/);
    const seal = api.calls.find((c) => c.url.endsWith("/seals"));
    expect(seal?.body).toEqual({
      path: BILLING,
      key: "db-password",
      value: "s3cr3t",
      regions: ["use2"],
    });

    // the change names its region, and the key is still missing in use1
    const pending = screen.getByRole("region", { name: /pending changes/i });
    const item = within(
      (await within(pending).findByText("db-password")).closest(
        "li",
      ) as HTMLElement,
    );
    expect(item.getByText("1 document in use2")).toBeInTheDocument();
    expect(
      item.getByRole("button", {
        name: `Remove db-password in use2 from ${BILLING}`,
      }),
    ).toBeInTheDocument();
    const keys = within(panel).getByRole("list", { name: "Keys" });
    await waitFor(() =>
      expect(
        within(keys).getByRole("button", { name: /^db-password/ }),
      ).toHaveTextContent("Missing in use1"),
    );
    expect(
      within(keys).getByRole("button", {
        name: "use2: pending. Seal db-password for use2 only",
      }),
    ).toBeInTheDocument();
    // the regions chosen stay for the next value
    expect(
      within(regions).getByRole("button", { name: /use1/ }),
    ).toHaveAttribute("aria-pressed", "false");
  });

  it("shows a Kustomize base's regions, which can't be sealed apart", async () => {
    const BASE = "deploy/payments/base/sealed-secret.yaml";
    const api = fakeApi({
      me: ME,
      files: {
        "example-org/apps": listing({
          files: [
            {
              path: BASE,
              blob: "4444444444444444444444444444444444444444",
              documents: [
                {
                  index: 0,
                  name: "payments",
                  namespace: "apps",
                  regions: ["use1", "use2"],
                  scope: "strict",
                  keys: ["token"],
                },
              ],
            },
          ],
        }),
      },
    });
    renderAt(`${PAGE}?file=${encodeURIComponent(BASE)}`, api);
    const { form, key, value } = await openForm(BASE);

    // the key's regions show as chips, which pick nothing
    const panel = screen.getByRole("region", { name: BASE });
    const chips = within(panel).getByRole("list", { name: "token by region" });
    expect(within(chips).getAllByRole("listitem")).toHaveLength(2);
    expect(within(chips).queryByRole("button")).toBeNull();
    expect(within(chips).getByLabelText("use1: set")).toBeInTheDocument();
    expect(
      within(panel).getByText(
        "Pick a key to seal its value, or type a new one below.",
      ),
    ).toBeInTheDocument();
    // the form lists them, with why there is no choice
    expect(within(form).queryByRole("group", { name: "Regions" })).toBeNull();
    const listed = within(form).getByRole("list", { name: "Regions" });
    expect(
      within(listed)
        .getAllByRole("listitem")
        .map((li) => li.textContent),
    ).toEqual(["use1", "use2"]);
    expect(form).toHaveTextContent(
      "The value goes to use1 and use2: regions listed in one document share it, so they can't be sealed apart.",
    );
    // the document lists both
    expect(
      within(panel)
        .getByRole("rowheader", { name: "apps/payments" })
        .closest("tr"),
    ).toHaveTextContent(/use1use2/);

    fireEvent.change(key, { target: { value: "token" } });
    fireEvent.change(value, { target: { value: "v" } });
    fireEvent.keyDown(value, { key: "Enter", ctrlKey: true });
    await within(form).findByText(/sealed/i, { selector: "span" });
    // sealed for the document: no regions are named
    expect(api.calls.find((c) => c.url.endsWith("/seals"))?.body).toEqual({
      path: BASE,
      key: "token",
      value: "v",
    });
  });

  it("shows the one region of a file Kustomize keeps per region", async () => {
    const USE1 = "deploy/payments/overlays/use1/sealed-secret.yaml";
    renderAt(
      `${PAGE}?file=${encodeURIComponent(USE1)}`,
      fakeApi({
        me: ME,
        files: {
          "example-org/apps": listing({
            files: [
              {
                path: USE1,
                blob: "5555555555555555555555555555555555555555",
                documents: [
                  {
                    index: 0,
                    name: "payments",
                    namespace: "apps",
                    regions: ["use1"],
                    scope: "strict",
                    keys: ["token"],
                  },
                ],
              },
            ],
          }),
        },
      }),
    );
    const { form } = await openForm(USE1);
    const panel = screen.getByRole("region", { name: USE1 });
    const chips = within(panel).getByRole("list", { name: "token by region" });
    expect(within(chips).getByLabelText("use1: set")).toBeInTheDocument();
    expect(within(chips).queryByRole("button")).toBeNull();
    // one region, in the documents' words
    expect(
      within(panel).getByRole("button", { name: /^token/ }),
    ).toHaveTextContent("tokenSet");
    expect(form).toHaveTextContent("The value is for use1.");
    // and the file in the list carries it as a tag
    const files = screen.getByRole("list", { name: "Files" });
    expect(within(files).getByText("use1")).toHaveClass("font-mono");
  });

  it("keeps at least one region chosen, and seals everywhere with all", async () => {
    const api = fakeApi({ me: ME, files: { "example-org/apps": hinted() } });
    renderAt(PAGE, api);
    const { form, key, value } = await openForm();
    const regions = within(form).getByRole("group", { name: "Regions" });
    const chip = (r: string) =>
      within(regions).getByRole("button", { name: new RegExp(r) });
    expect(chip("use1")).toHaveAttribute("aria-pressed", "true");
    expect(chip("use2")).toHaveAttribute("aria-pressed", "true");

    fireEvent.click(chip("use1"));
    expect(chip("use1")).toHaveAttribute("aria-pressed", "false");
    // the last one chosen stays
    fireEvent.click(chip("use2"));
    expect(chip("use2")).toHaveAttribute("aria-pressed", "true");
    expect(within(form).getByText(/Only the documents in use2/)).toBeVisible();

    fireEvent.click(
      within(regions).getByRole("button", { name: "All Regions" }),
    );
    expect(chip("use1")).toHaveAttribute("aria-pressed", "true");
    fireEvent.change(key, { target: { value: "api-key" } });
    fireEvent.change(value, { target: { value: "v" } });
    fireEvent.keyDown(value, { key: "Enter", ctrlKey: true });
    await within(form).findByText(/sealed/i, { selector: "span" });
    // every region is every document: no regions are sent
    expect(api.calls.find((c) => c.url.endsWith("/seals"))?.body).toEqual({
      path: BILLING,
      key: "api-key",
      value: "v",
    });
  });
});

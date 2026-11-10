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

const APPS = "/repos/example-org/apps";
const BILLING = "deploy/billing/sealed-secret.yaml";

async function openForm() {
  const billing = await screen.findByRole("region", { name: BILLING });
  fireEvent.click(
    within(billing).getByRole("button", { name: "Seal a value" }),
  );
  const form = within(billing).getByRole("form", {
    name: `Seal a value into ${BILLING}`,
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
    renderAt(APPS, api);

    // files that cannot be sealed into say why
    const legacy = await screen.findByRole("region", {
      name: "deploy/legacy/sealed-secret.yaml",
    });
    expect(
      within(legacy).getByRole("button", { name: "Seal a value" }),
    ).toBeDisabled();

    const { form, key, value, seal } = await openForm();
    expect(within(form).getByText(/each of the 2 documents/)).toBeVisible();
    expect(seal).toBeDisabled();
    fireEvent.change(key, { target: { value: "api-token" } });
    fireEvent.change(value, { target: { value: "s3cr3t" } });
    fireEvent.click(seal);

    expect(
      await within(form).findByText(/sealed/i, { selector: "span" }),
    ).toHaveTextContent(/Sealed api-token for 2 documents in dev-use1-blue/);
    expect(value).toHaveValue("");
    expect(key).toHaveValue("");

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

    // the pending change appears
    const pending = await screen.findByRole("region", {
      name: /pending changes/i,
    });
    const row = await within(pending).findByRole("rowheader", {
      name: BILLING,
    });
    const cells = within(row.closest("tr") as HTMLElement);
    expect(cells.getByText("api-token")).toBeInTheDocument();
    expect(cells.getByText("2 documents")).toBeInTheDocument();
    expect(cells.getByText("dev-use1-blue")).toBeInTheDocument();
  });

  it("keeps the value when a seal fails, and says why", async () => {
    renderAt(
      APPS,
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
      APPS,
      fakeApi({ me: ME, files: { "example-org/apps": listing() } }),
    );
    const { form, key, value, seal } = await openForm();
    fireEvent.change(value, { target: { value: "v" } });
    fireEvent.change(key, { target: { value: "a/b" } });
    expect(within(form).getByText(/letters, digits/)).toBeVisible();
    expect(key).toHaveAttribute("aria-invalid", "true");
    expect(seal).toBeDisabled();
    fireEvent.change(key, { target: { value: "api-key" } });
    expect(
      within(form).getByText("Replaces the existing value of api-key."),
    ).toBeVisible();
    expect(seal).toBeEnabled();
    // the value is masked until shown
    expect(value.className).toContain("[-webkit-text-security:disc]");
    fireEvent.click(within(form).getByRole("button", { name: "Show" }));
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
    renderAt(APPS, api);
    const pending = await screen.findByRole("region", {
      name: /pending changes/i,
    });
    expect(within(pending).getAllByRole("row")).toHaveLength(3);
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
    expect(within(pending).getAllByRole("row")).toHaveLength(2);

    fireEvent.click(within(pending).getByRole("button", { name: "Discard" }));
    const dialog = await screen.findByRole("dialog", {
      name: "Discard pending changes?",
    });
    expect(dialog).toHaveTextContent("This removes 1 pending change");
    fireEvent.click(within(dialog).getByRole("button", { name: "Discard" }));
    await waitFor(() =>
      expect(
        screen.queryByRole("region", { name: /pending changes/i }),
      ).not.toBeInTheDocument(),
    );
    expect(
      api.calls.filter((c) => c.method === "DELETE").map((c) => c.url),
    ).toEqual([
      `${APPS}/session/${SESSION.id}/changes/${changeFor({ ...SEAL, key: "password" }).id}`,
      `${APPS}/session/${SESSION.id}`,
    ]);
  });

  it("offers no sealing to read-only users", async () => {
    renderAt(
      "/repos/example-org/platform",
      fakeApi({
        me: ME,
        files: {
          "example-org/platform": listing({ repository: REPO_PLATFORM }),
        },
      }),
    );
    await screen.findByRole("region", { name: BILLING });
    expect(
      screen.queryByRole("button", { name: "Seal a value" }),
    ).not.toBeInTheDocument();
  });

  it("marks repositories with pending changes", async () => {
    renderAt(
      "/repos",
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
      await within(apps).findByText("2 pending changes"),
    ).toBeInTheDocument();
  });
});

import { describe, it, expect, afterEach } from "vitest";
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
  SESSION,
  fakeApi,
  listing,
  type FakeApi,
} from "@/test/fake-api";

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
  return router;
}

describe("repositories", () => {
  const originalAdapter = apiClient.defaults.adapter;
  afterEach(() => {
    apiClient.defaults.adapter = originalAdapter;
  });

  it("lists the repositories the user can read, with their access", async () => {
    renderAt(
      "/secrets",
      fakeApi({ me: ME, repos: [REPO_APPS, REPO_PLATFORM] }),
    );

    const apps = await screen.findByRole("rowheader", {
      name: "example-org/apps",
    });
    const appsRow = apps.closest("tr") as HTMLElement;
    expect(within(appsRow).getByText("Write")).toBeInTheDocument();
    expect(within(appsRow).getByText("Private")).toBeInTheDocument();
    expect(
      within(apps).getByRole("link", { name: "example-org/apps" }),
    ).toHaveAttribute("href", "/dev/secrets/example-org/apps");

    const platform = screen
      .getByRole("rowheader", { name: "example-org/platform" })
      .closest("tr") as HTMLElement;
    expect(within(platform).getByText("Read Only")).toBeInTheDocument();

    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).getByRole("link", { name: "Secrets" })).toHaveAttribute(
      "aria-current",
      "page",
    );
  });

  it("lists the repositories worked in lately first, opening the file last sealed into", async () => {
    // what this browser remembers for the user in dev: a repository they
    // can no longer read is left out
    localStorage.setItem(
      "sealer.recent-repos:octocat:dev",
      JSON.stringify([
        {
          repository: "example-org/platform",
          path: "secrets/dev/sealed-secret.yaml",
          sealed_at: new Date(Date.now() - 3 * 60_000).toISOString(),
        },
        {
          repository: "example-org/gone",
          path: "x.yaml",
          sealed_at: new Date(Date.now() - 4 * 60_000).toISOString(),
        },
      ]),
    );
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
    const recent = await screen.findByRole("region", {
      name: "Recent Repositories",
    });
    // pending changes first, then the latest seals
    await waitFor(() =>
      expect(within(recent).getAllByRole("link")[0]).toHaveTextContent(
        "example-org/apps",
      ),
    );
    const [apps] = within(recent).getAllByRole("link");
    expect(apps).toHaveTextContent("2 Pending Changes");
    expect(apps).toHaveAttribute("href", "/dev/secrets/example-org/apps");
    const platform = within(recent).getAllByRole("link")[1] as HTMLElement;
    expect(platform).toHaveTextContent("example-org/platform");
    expect(platform).toHaveTextContent("Sealed 3m ago");
    expect(platform).toHaveAttribute(
      "href",
      "/dev/secrets/example-org/platform?file=secrets%2Fdev%2Fsealed-secret.yaml",
    );
    expect(within(recent).getAllByRole("link")).toHaveLength(2);
    // the full list still follows
    expect(
      screen.getByRole("rowheader", { name: "example-org/platform" }),
    ).toBeInTheDocument();
  });

  it("shows no recent repositories before any work", async () => {
    renderAt(
      "/secrets",
      fakeApi({ me: ME, repos: [REPO_APPS, REPO_PLATFORM] }),
    );
    await screen.findByRole("rowheader", { name: "example-org/apps" });
    expect(
      screen.queryByRole("region", { name: "Recent Repositories" }),
    ).not.toBeInTheDocument();
  });

  it("names a file by its title, over its path, and filters by it", async () => {
    const base = listing();
    const [billing, ...rest] = base.files;
    renderAt(
      "/secrets/example-org/apps",
      fakeApi({
        me: ME,
        files: {
          "example-org/apps": listing({
            files: [
              {
                ...billing!,
                documents: (billing!.documents ?? []).map((d) => ({
                  ...d,
                  title: "Billing provider",
                })),
              },
              ...rest,
            ],
          }),
        },
      }),
    );
    const files = await screen.findByRole("list", { name: "Files" });
    const button = within(files).getAllByRole("button")[0] as HTMLElement;
    expect(button).toHaveAccessibleName(
      /^Billing providerdeploy\/billing\/sealed-secret\.yaml/,
    );
    expect(within(button).getByText("Billing provider")).toHaveClass(
      "truncate",
    );
    // the header names it too, with its path under it
    const panel = screen.getByRole("region", {
      name: "deploy/billing/sealed-secret.yaml",
    });
    expect(within(panel).getByRole("heading", { level: 2 })).toHaveTextContent(
      /^Billing provider$/,
    );
    expect(
      within(panel).getByRole("button", { name: "Copy file path" }),
    ).toBeInTheDocument();
    fireEvent.change(screen.getByRole("searchbox", { name: "Filter files" }), {
      target: { value: "provider" },
    });
    expect(within(files).getAllByRole("button")).toHaveLength(1);
  });

  it("says when repositories may be missing from the list", async () => {
    renderAt(
      "/secrets",
      fakeApi({ me: ME, repos: [REPO_APPS], reposIncomplete: true }),
    );
    expect(
      await screen.findByRole("rowheader", { name: "example-org/apps" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent(
      /some repositories may be missing/i,
    );
  });

  it("does not call a list with none checked in time empty", async () => {
    renderAt("/secrets", fakeApi({ me: ME, repos: [], reposIncomplete: true }));
    expect(await screen.findByRole("status")).toHaveTextContent(
      /some repositories may be missing/i,
    );
    expect(screen.queryByText("No Repositories")).not.toBeInTheDocument();
  });

  it("explains an empty list and shows errors", async () => {
    renderAt("/secrets", fakeApi({ me: ME, repos: [] }));
    expect(await screen.findByText("No Repositories")).toBeInTheDocument();
  });

  it("shows the server's message when GitHub fails", async () => {
    renderAt("/secrets", fakeApi({ me: ME, reposStatus: 502 }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /could not load repositories/i,
    );
  });

  it("shows a repository's SealedSecret files for the env", async () => {
    renderAt(
      "/secrets/example-org/apps",
      fakeApi({ me: ME, files: { "example-org/apps": listing() } }),
    );

    // every file, with whether values fit in it
    const files = await screen.findByRole("list", { name: "Files" });
    const buttons = within(files).getAllByRole("button");
    expect(buttons).toHaveLength(3);
    // each path on one line, read whole (the page's layout, which jsdom
    // lacks, puts the lines apart) and whole in its title
    expect(buttons[0]).toHaveAccessibleName(
      "deploy/billing/sealed-secret.yaml2 documents · use1, use2",
    );
    expect(buttons[1]).toHaveAccessibleName(
      "deploy/legacy/sealed-secret.yaml1 document · Can't Seal",
    );
    expect(buttons[2]).toHaveAccessibleName(
      "deploy/broken/sealed-secret.yamlUnreadable",
    );
    expect(
      within(buttons[0]!).getByTitle("deploy/billing/sealed-secret.yaml"),
    ).toHaveClass("flex");

    // the first file values fit in is open
    const billing = screen.getByRole("region", {
      name: "deploy/billing/sealed-secret.yaml",
    });
    expect(
      within(billing).getByRole("rowheader", {
        name: "dev-use1-blue-apps/billing",
      }),
    ).toBeInTheDocument();
    expect(within(billing).getByText("api-key")).toBeInTheDocument();
    expect(
      within(billing).getAllByRole("button", { name: /^Strict scope/ }),
    ).toHaveLength(2);

    fireEvent.click(buttons[2] as HTMLElement);
    // an unreadable file is a failure, in the panel as in the list
    const unreadable = await screen.findByRole("alert");
    expect(unreadable).toHaveTextContent(/could not read this file/i);
    expect(unreadable).toHaveTextContent("File is not valid YAML.");
    expect(screen.getByText("0123456")).toBeInTheDocument();
    expect(screen.queryByText(/not write to it/)).not.toBeInTheDocument();
  });

  it("filters repositories and opens the first match with Enter", async () => {
    const router = renderAt(
      "/secrets",
      fakeApi({ me: ME, repos: [REPO_APPS, REPO_PLATFORM] }),
    );
    const filter = await screen.findByRole("searchbox", {
      name: "Filter repositories",
    });
    fireEvent.change(filter, { target: { value: "plat" } });
    expect(screen.getAllByRole("rowheader")).toHaveLength(1);
    expect(screen.getByText("1 of 2")).toBeInTheDocument();
    fireEvent.keyDown(filter, { key: "Enter" });
    await waitFor(() =>
      expect(router.state.location.pathname).toBe(
        "/dev/secrets/example-org/platform",
      ),
    );
  });

  it("says when the user can only read, and when nothing was found", async () => {
    renderAt(
      "/secrets/example-org/platform",
      fakeApi({
        me: ME,
        files: {
          "example-org/platform": listing({
            repository: REPO_PLATFORM,
            files: [],
          }),
        },
      }),
    );
    expect(await screen.findByText(/not write to it/)).toBeInTheDocument();
    expect(screen.getByText("No SealedSecrets for dev")).toBeInTheDocument();
    expect(screen.getByText("*sealed*.yaml")).toBeInTheDocument();
  });

  it("reports a repository the user cannot read as not found, with the way back", async () => {
    renderAt("/secrets/example-org/restricted", fakeApi({ me: ME }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/repository not found/i);
    expect(alert).toHaveTextContent("example-org/restricted doesn't exist");
    expect(
      within(alert).getByRole("link", { name: "Back to Secrets" }),
    ).toHaveAttribute("href", "/dev/secrets");
  });

  it("shows the table's shape and a disabled filter while loading", async () => {
    const api = fakeApi({ me: ME, repos: [REPO_APPS] });
    // the repository list never answers
    renderAt("/secrets", {
      ...api,
      adapter: (config) =>
        config.url?.endsWith("/repos")
          ? new Promise(() => {})
          : api.adapter(config),
    });
    const loading = await screen.findByLabelText("Loading repositories");
    expect(within(loading).getByRole("table")).toBeInTheDocument();
    expect(
      screen.getByRole("searchbox", { name: "Filter repositories" }),
    ).toBeDisabled();
  });

  it("offers to clear a filter that matches nothing", async () => {
    renderAt(
      "/secrets",
      fakeApi({ me: ME, repos: [REPO_APPS, REPO_PLATFORM] }),
    );
    const filter = await screen.findByRole("searchbox", {
      name: "Filter repositories",
    });
    fireEvent.change(filter, { target: { value: "nope" } });
    expect(
      screen.getByText("No repository matches “nope”."),
    ).toBeInTheDocument();
    // one in the field, which replaces its shortcut hint, and one with the
    // empty result
    const clear = screen.getAllByRole("button", { name: "Clear Filter" });
    expect(clear).toHaveLength(2);
    fireEvent.click(clear[1] as HTMLElement);
    expect(filter).toHaveValue("");
    expect(screen.getAllByRole("rowheader")).toHaveLength(2);
  });
});

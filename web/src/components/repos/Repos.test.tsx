import { describe, it, expect, afterEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
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
    renderAt("/repos", fakeApi({ me: ME, repos: [REPO_APPS, REPO_PLATFORM] }));

    const apps = await screen.findByRole("rowheader", {
      name: "example-org/apps",
    });
    const appsRow = apps.closest("tr") as HTMLElement;
    expect(within(appsRow).getByText("Write")).toBeInTheDocument();
    expect(within(appsRow).getByText("Private")).toBeInTheDocument();
    expect(
      within(apps).getByRole("link", { name: "example-org/apps" }),
    ).toHaveAttribute("href", "/repos/example-org/apps");

    const platform = screen
      .getByRole("rowheader", { name: "example-org/platform" })
      .closest("tr") as HTMLElement;
    expect(within(platform).getByText("Read only")).toBeInTheDocument();

    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(
      within(nav).getByRole("link", { name: "Repositories" }),
    ).toHaveAttribute("aria-current", "page");
  });

  it("explains an empty list and shows errors", async () => {
    renderAt("/repos", fakeApi({ me: ME, repos: [] }));
    expect(await screen.findByText("No repositories")).toBeInTheDocument();
  });

  it("shows the server's message when GitHub fails", async () => {
    renderAt("/repos", fakeApi({ me: ME, reposStatus: 502 }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /could not load repositories/i,
    );
  });

  it("shows a repository's SealedSecret files for the env", async () => {
    renderAt(
      "/repos/example-org/apps",
      fakeApi({ me: ME, files: { "example-org/apps": listing() } }),
    );

    const billing = await screen.findByRole("region", {
      name: "deploy/billing/sealed-secret.yaml",
    });
    expect(within(billing).getByText("2 documents")).toBeInTheDocument();
    expect(
      within(billing).getByRole("rowheader", {
        name: "dev-use1-blue-apps/billing",
      }),
    ).toBeInTheDocument();
    expect(within(billing).getByText("api-key")).toBeInTheDocument();
    expect(within(billing).getAllByText("Ready")).toHaveLength(2);

    const legacy = screen.getByRole("region", {
      name: "deploy/legacy/sealed-secret.yaml",
    });
    expect(within(legacy).getByText("Can't seal")).toBeInTheDocument();
    expect(within(legacy).getByText(/cluster-wide scope/)).toBeInTheDocument();

    expect(
      screen.getByText(/could not read this file: file is not valid yaml/i),
    ).toBeInTheDocument();
    expect(screen.getByText("0123456")).toBeInTheDocument();
    expect(screen.queryByText(/not write to it/)).not.toBeInTheDocument();
  });

  it("says when the user can only read, and when nothing was found", async () => {
    renderAt(
      "/repos/example-org/platform",
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

  it("reports a repository the user cannot read as not found", async () => {
    renderAt("/repos/example-org/restricted", fakeApi({ me: ME }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /could not load this repository/i,
    );
  });
});

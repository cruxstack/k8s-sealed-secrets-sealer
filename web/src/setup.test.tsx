import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { AxiosError, type AxiosAdapter } from "axios";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRouter,
  RouterProvider,
} from "@tanstack/react-router";
import apiClient, { navigation, setApiEnv } from "@/api/client";
import type { SetupStatus } from "@/api/types";
import { ThemeProvider } from "@/lib/theme-provider";
import { routeTree } from "@/routeTree.gen";

const SETUP: SetupStatus = {
  org: "example-org",
  github_url: "https://github.com",
  public_url: "https://sealer.example.com",
  app_name: "Sealer for example-org",
  permissions: [
    { name: "contents", access: "write" },
    { name: "pull_requests", access: "write" },
    { name: "metadata", access: "read" },
    { name: "members", access: "read" },
  ],
};

/** The setup API: the status, or 404 once set up, and the form. */
function setupApi(opts: { setup: SetupStatus | null; startStatus?: number }) {
  const calls: { method: string; url: string; xhr: unknown }[] = [];
  const adapter: AxiosAdapter = async (config) => {
    const method = (config.method ?? "get").toUpperCase();
    const url = config.url ?? "";
    calls.push({
      method,
      url,
      xhr: config.headers?.get?.("X-Requested-With"),
    });
    const reply = (status: number, data: unknown) => {
      const response = {
        data,
        status,
        statusText: "",
        headers: {},
        config,
      };
      if (status >= 400) {
        throw new AxiosError("fail", "ERR", config, undefined, response);
      }
      return response;
    };
    if (url === "/auth/me") return reply(503, { error: "not set up" });
    if (url === "/setup" && method === "GET") {
      return opts.setup ? reply(200, opts.setup) : reply(404, {});
    }
    if (url === "/setup/github-app" && method === "POST") {
      if (opts.startStatus) {
        return reply(opts.startStatus, { error: "Too many requests." });
      }
      return reply(200, {
        action:
          "https://github.com/organizations/example-org/settings/apps/new?state=s1",
        manifest: '{"name":"Sealer for example-org"}',
      });
    }
    return reply(404, {});
  };
  return { adapter, calls };
}

function renderSetup(path: string) {
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

describe("GitHub App setup page", () => {
  const originalAdapter = apiClient.defaults.adapter;
  const originalPostForm = navigation.postForm;

  beforeEach(() => {
    navigation.postForm = vi.fn();
  });

  afterEach(() => {
    apiClient.defaults.adapter = originalAdapter;
    navigation.postForm = originalPostForm;
    setApiEnv(null);
  });

  it("posts the App's manifest to GitHub in the org", async () => {
    const api = setupApi({ setup: SETUP });
    apiClient.defaults.adapter = api.adapter;
    // a page left in an env still asks the setup API, not the env's
    setApiEnv("dev");
    renderSetup("/setup");

    const create = await screen.findByRole("button", {
      name: /create the github app in example-org/i,
    });
    expect(screen.getByText("Pull Requests")).toBeInTheDocument();
    expect(screen.getByText("Members (Organization)")).toBeInTheDocument();
    expect(screen.getAllByText("Read and Write")).toHaveLength(2);

    fireEvent.click(create);
    await waitFor(() => expect(navigation.postForm).toHaveBeenCalledTimes(1));
    expect(navigation.postForm).toHaveBeenCalledWith(
      "https://github.com/organizations/example-org/settings/apps/new?state=s1",
      { manifest: '{"name":"Sealer for example-org"}' },
    );
    const start = api.calls.find((c) => c.url === "/setup/github-app");
    expect(start?.method).toBe("POST");
    expect(start?.xhr).toBe("XMLHttpRequest");
  });

  it("says why the last setup stopped, without echoing the code", async () => {
    apiClient.defaults.adapter = setupApi({ setup: SETUP }).adapter;
    renderSetup("/setup?error=wrong_owner");
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /outside the organization/,
    );
  });

  it("shows a failure to start, and lets the person try again", async () => {
    apiClient.defaults.adapter = setupApi({
      setup: SETUP,
      startStatus: 429,
    }).adapter;
    renderSetup("/setup");
    fireEvent.click(
      await screen.findByRole("button", { name: /create the github app/i }),
    );
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    expect(navigation.postForm).not.toHaveBeenCalled();
    expect(
      screen.getByRole("button", { name: /create the github app/i }),
    ).toBeEnabled();
  });

  it("points to signing in once the App is set up", async () => {
    apiClient.defaults.adapter = setupApi({ setup: null }).adapter;
    renderSetup("/setup");
    expect(await screen.findByText("Sealer Is Set Up")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Sign In" })).toHaveAttribute(
      "href",
      "/login",
    );
    expect(
      screen.queryByRole("button", { name: /create the github app/i }),
    ).not.toBeInTheDocument();
  });
});

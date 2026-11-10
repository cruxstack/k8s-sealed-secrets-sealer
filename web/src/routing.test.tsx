import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { StrictMode } from "react";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRouter,
  RouterProvider,
} from "@tanstack/react-router";
import apiClient, { navigation } from "@/api/client";
import { ThemeProvider } from "@/lib/theme-provider";
import { routeTree } from "@/routeTree.gen";
import { ADMIN, ME, fakeApi, listing } from "@/test/fake-api";

function renderApp(path: string) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const router = createRouter({
    routeTree,
    context: { queryClient },
    history: createMemoryHistory({ initialEntries: [path] }),
  });
  let navigations = 0;
  router.subscribe("onBeforeNavigate", () => {
    navigations++;
  });
  render(
    <StrictMode>
      <ThemeProvider defaultTheme="light" storageKey="test-theme">
        <QueryClientProvider client={queryClient}>
          <RouterProvider router={router} />
        </QueryClientProvider>
      </ThemeProvider>
    </StrictMode>,
  );
  return { router, navigations: () => navigations };
}

describe("auth routing", () => {
  const originalAdapter = apiClient.defaults.adapter;
  const originalAssign = navigation.assign;

  beforeEach(() => {
    navigation.assign = vi.fn();
  });

  afterEach(() => {
    apiClient.defaults.adapter = originalAdapter;
    navigation.assign = originalAssign;
  });

  // Regression: a render-time <Navigate> restarted its own navigation on
  // every router state change and froze the page for signed-out users.
  it("sends a signed-out visitor from / to the login page once", async () => {
    const api = fakeApi({ me: null });
    apiClient.defaults.adapter = api.adapter;
    const { router, navigations } = renderApp("/");

    expect(
      await screen.findByRole("link", { name: /sign in with github/i }),
    ).toBeInTheDocument();
    await waitFor(() => expect(router.state.status).toBe("idle"));
    expect(router.state.location.pathname).toBe("/login");
    expect(navigations()).toBeLessThanOrEqual(3);
    expect(api.calls.filter((c) => c.url === "/auth/me")).toHaveLength(1);
    expect(api.calls.map((c) => c.url)).not.toContain("/fleet");
    expect(navigation.assign).not.toHaveBeenCalled();
  });

  it("shows the login page with its error message to signed-out visitors", async () => {
    apiClient.defaults.adapter = fakeApi({ me: null }).adapter;
    const { router } = renderApp("/login?error=not_member");

    expect(
      await screen.findByText(/member of the GitHub organization/i),
    ).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/login");
  });

  it("carries return_to through the sign-in link, but only same-origin paths", async () => {
    apiClient.defaults.adapter = fakeApi({ me: null }).adapter;
    renderApp("/login?return_to=%2Fsomewhere%3Fx%3D1");
    const link = await screen.findByRole("link", {
      name: /sign in with github/i,
    });
    expect(link).toHaveAttribute(
      "href",
      "/api/v1/auth/login?return_to=%2Fsomewhere%3Fx%3D1",
    );
  });

  it("ignores an off-site return_to", async () => {
    apiClient.defaults.adapter = fakeApi({ me: null }).adapter;
    renderApp("/login?return_to=%2F%2Fevil.example.com");
    const link = await screen.findByRole("link", {
      name: /sign in with github/i,
    });
    expect(link).toHaveAttribute("href", "/api/v1/auth/login");
  });

  it("sends a signed-in user from /login to their secrets", async () => {
    const api = fakeApi({ me: ME });
    apiClient.defaults.adapter = api.adapter;
    const { router, navigations } = renderApp("/login");

    expect(
      await screen.findByRole("button", { name: /account menu for octocat/i }),
    ).toBeInTheDocument();
    await waitFor(() => expect(router.state.status).toBe("idle"));
    expect(router.state.location.pathname).toBe("/secrets");
    expect(navigations()).toBeLessThanOrEqual(4);
    expect(
      screen.queryByRole("link", { name: /sign in with github/i }),
    ).not.toBeInTheDocument();
  });

  it("keeps old /repos links working, with their file", async () => {
    apiClient.defaults.adapter = fakeApi({
      me: ME,
      files: { "example-org/apps": listing() },
    }).adapter;
    const { router } = renderApp(
      "/repos/example-org/apps?file=deploy%2Flegacy%2Fsealed-secret.yaml",
    );

    await screen.findByRole("region", {
      name: "deploy/legacy/sealed-secret.yaml",
    });
    expect(router.state.location.pathname).toBe("/secrets/example-org/apps");
    expect(router.state.location.search).toEqual({
      file: "deploy/legacy/sealed-secret.yaml",
    });
  });

  it("tells people who are not admins that the fleet is for admins", async () => {
    const api = fakeApi({ me: ME });
    apiClient.defaults.adapter = api.adapter;
    renderApp("/fleet");

    expect(
      await screen.findByRole("heading", { name: "The fleet is for admins" }),
    ).toBeInTheDocument();
    expect(api.calls.map((c) => c.url)).not.toContain("/fleet");
  });

  it("shows admins the fleet", async () => {
    apiClient.defaults.adapter = fakeApi({ me: ADMIN }).adapter;
    renderApp("/fleet");

    expect(
      await screen.findByRole("heading", { name: "Agents" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("The fleet is for admins"),
    ).not.toBeInTheDocument();
  });
});

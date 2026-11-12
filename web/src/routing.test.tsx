import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { StrictMode } from "react";
import { render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRouter,
  RouterProvider,
} from "@tanstack/react-router";
import apiClient, { navigation } from "@/api/client";
import { ThemeProvider } from "@/lib/theme-provider";
import { routeTree } from "@/routeTree.gen";
import {
  ADMIN,
  ME,
  REPO_APPS,
  TWO_ENVS,
  fakeApi,
  listing,
} from "@/test/fake-api";

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
    expect(router.state.location.pathname).toBe("/dev/secrets");
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
    expect(router.state.location.pathname).toBe(
      "/dev/secrets/example-org/apps",
    );
    expect(router.state.location.search).toEqual({
      file: "deploy/legacy/sealed-secret.yaml",
    });
  });

  it("tells people who are not admins that the fleet is for admins", async () => {
    const api = fakeApi({ me: ME });
    apiClient.defaults.adapter = api.adapter;
    renderApp("/fleet");

    expect(
      await screen.findByRole("heading", { name: "The Fleet Is for Admins" }),
    ).toBeInTheDocument();
    expect(api.calls.map((c) => c.url)).not.toContain("/fleet");
  });

  it("shows admins the fleet, marked as the current page", async () => {
    apiClient.defaults.adapter = fakeApi({ me: ADMIN }).adapter;
    renderApp("/fleet");

    expect(
      await screen.findByRole("heading", { name: "Agents" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("The Fleet Is for Admins"),
    ).not.toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).getByRole("link", { name: "Fleet" })).toHaveAttribute(
      "aria-current",
      "page",
    );
    expect(
      within(nav).getByRole("link", { name: "Secrets" }),
    ).not.toHaveAttribute("aria-current");
  });

  it("shows a page that does not exist in the app's shell, with the way home", async () => {
    apiClient.defaults.adapter = fakeApi({ me: ME }).adapter;
    renderApp("/dev/no-such-page");

    expect(
      await screen.findByRole("heading", { level: 1, name: "Page Not Found" }),
    ).toBeInTheDocument();
    expect(screen.getByText("/dev/no-such-page")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Go to Secrets" })).toHaveAttribute(
      "href",
      "/",
    );
    // inside the shell: the header and its account menu are there
    expect(
      screen.getByRole("button", { name: /account menu for octocat/i }),
    ).toBeInTheDocument();
  });

  it("shows a deeper unknown path as not found too", async () => {
    apiClient.defaults.adapter = fakeApi({ me: ME }).adapter;
    renderApp("/dev/secrets/example-org/apps/extra/parts");
    expect(
      await screen.findByRole("heading", { level: 1, name: "Page Not Found" }),
    ).toBeInTheDocument();
  });

  it("puts every page in an env, starting with the user's first", async () => {
    const api = fakeApi({ me: TWO_ENVS, repos: [REPO_APPS] });
    apiClient.defaults.adapter = api.adapter;
    const { router } = renderApp("/");
    await waitFor(() =>
      expect(router.state.location.pathname).toBe("/dev/secrets"),
    );
    await screen.findByRole("rowheader", { name: /example-org\/apps/ });
    expect(api.calls.find((c) => c.url === "/repos")?.env).toBe("dev");

    // another env loads its own data
    await router.navigate({ to: "/$env/secrets", params: { env: "prod" } });
    await screen.findByRole("button", {
      name: /^Environment prod.*Switch environment$/,
    });
    await waitFor(() =>
      expect(
        api.calls.filter((c) => c.url === "/repos").map((c) => c.env),
      ).toEqual(["dev", "prod"]),
    );
  });

  it("says when the user may not use an env", async () => {
    const api = fakeApi({ me: ME });
    apiClient.defaults.adapter = api.adapter;
    renderApp("/prod/secrets/example-org/apps");
    expect(
      await screen.findByRole("heading", {
        name: "You Can't Use the prod Env",
      }),
    ).toBeInTheDocument();
    // the way forward is a button-styled link
    expect(screen.getByRole("link", { name: "Go to dev" })).toHaveAttribute(
      "href",
      "/dev/secrets",
    );
    // nothing was asked of prod
    expect(api.calls.filter((c) => c.env === "prod")).toEqual([]);
  });
});

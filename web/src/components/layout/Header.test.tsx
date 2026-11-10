import { describe, it, expect, afterEach, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRootRoute,
  createRouter,
  RouterProvider,
} from "@tanstack/react-router";
import apiClient, { navigation, setApiEnv } from "@/api/client";
import type { MeResponse, SealingStatus } from "@/api/types";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AuthProvider } from "@/lib/auth";
import { EnvProvider } from "@/lib/env";
import { ThemeProvider } from "@/lib/theme-provider";
import { Header } from "./Header";
import { ADMIN, ME, TWO_ENVS, fakeApi } from "@/test/fake-api";

/** The header of a page in env (the user's first, by default). */
function renderHeader(
  me: MeResponse,
  status?: SealingStatus,
  env = me.envs[0]!,
) {
  const api = fakeApi({ me, status });
  apiClient.defaults.adapter = api.adapter;
  setApiEnv(env.name);
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  // the header's navigation links need a router
  const router = createRouter({
    routeTree: createRootRoute({
      component: () => (
        <TooltipProvider>
          <AuthProvider>
            <EnvProvider env={env}>
              <Header />
            </EnvProvider>
          </AuthProvider>
        </TooltipProvider>
      ),
    }),
    history: createMemoryHistory({ initialEntries: ["/"] }),
  });
  render(
    <ThemeProvider defaultTheme="light" storageKey="test-theme">
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </ThemeProvider>,
  );
  return api;
}

describe("Header", () => {
  const originalAdapter = apiClient.defaults.adapter;
  const originalAssign = navigation.assign;

  afterEach(() => {
    apiClient.defaults.adapter = originalAdapter;
    navigation.assign = originalAssign;
  });

  it("shows the env and whether sealing works, and signs out with the CSRF token", async () => {
    const assign = vi.fn();
    navigation.assign = assign;
    const api = renderHeader(ME, {
      env: "dev",
      sealing: "degraded",
      message: "Sealing works, but 1 of 3 clusters are down or missing keys.",
      clusters: { ready: 2, total: 3 },
    });

    const trigger = await screen.findByRole("button", {
      name: /account menu for octocat/i,
    });
    // not an admin: the badge says how sealing goes but leads nowhere
    const badge = await screen.findByRole("button", {
      name: "Environment dev: sealing works, some clusters are not ready",
    });
    expect(badge).toHaveTextContent("dev");
    expect(
      screen.queryByRole("link", { name: /open the fleet/i }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Secrets" })).toHaveAttribute(
      "href",
      "/dev/secrets",
    );

    fireEvent.keyDown(trigger, { key: "Enter" });
    await screen.findByRole("menuitem", { name: /sign out/i });
    expect(
      screen.queryByRole("menuitem", { name: /fleet/i }),
    ).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("menuitem", { name: /sign out/i }));

    await waitFor(() => expect(assign).toHaveBeenCalledWith("/login"));
    const logout = api.calls.find((c) => c.url === "/auth/logout");
    // signing out is for every env at once
    expect(logout).toEqual({
      method: "POST",
      url: "/auth/logout",
      env: undefined,
      csrf: ME.csrf_token,
    });
  });

  it("leads admins to the fleet from the env badge and the account menu", async () => {
    renderHeader(ADMIN);

    expect(
      await screen.findByRole("link", {
        name: "Environment dev: sealing works. Open the fleet",
      }),
    ).toHaveAttribute("href", "/dev/fleet");

    fireEvent.keyDown(
      screen.getByRole("button", { name: /account menu for octocat/i }),
      { key: "Enter" },
    );
    expect(
      await screen.findByRole("menuitem", { name: /fleet/i }),
    ).toHaveAttribute("href", "/dev/fleet");
  });

  it("switches between the envs a user may use, and leads to the fleets they administer", async () => {
    renderHeader(TWO_ENVS, undefined, TWO_ENVS.envs[1]);

    const switcher = await screen.findByRole("button", {
      name: "Environment prod: sealing works. Switch environment",
    });
    fireEvent.keyDown(switcher, { key: "Enter" });
    const items = await screen.findAllByRole("menuitem");
    expect(items.map((i) => i.textContent)).toEqual([
      "dev",
      "prodadmin",
      "Open the prod fleet",
    ]);
    expect(screen.getByRole("menuitem", { name: /^prod/ })).toHaveAttribute(
      "aria-current",
      "true",
    );
    expect(
      screen.getByRole("menuitem", { name: "Open the prod fleet" }),
    ).toHaveAttribute("href", "/prod/fleet");
  });
});

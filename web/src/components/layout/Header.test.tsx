import { describe, it, expect, afterEach, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRootRoute,
  createRouter,
  RouterProvider,
} from "@tanstack/react-router";
import apiClient, { navigation } from "@/api/client";
import type { MeResponse, SealingStatus } from "@/api/types";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AuthProvider } from "@/lib/auth";
import { ThemeProvider } from "@/lib/theme-provider";
import { Header } from "./Header";
import { ADMIN, ME, fakeApi } from "@/test/fake-api";

function renderHeader(me: MeResponse, status?: SealingStatus) {
  const api = fakeApi({ me, status });
  apiClient.defaults.adapter = api.adapter;
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  // the header's navigation links need a router
  const router = createRouter({
    routeTree: createRootRoute({
      component: () => (
        <TooltipProvider>
          <AuthProvider>
            <Header />
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
      "/secrets",
    );

    fireEvent.keyDown(trigger, { key: "Enter" });
    await screen.findByRole("menuitem", { name: /sign out/i });
    expect(
      screen.queryByRole("menuitem", { name: /fleet/i }),
    ).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("menuitem", { name: /sign out/i }));

    await waitFor(() => expect(assign).toHaveBeenCalledWith("/login"));
    const logout = api.calls.find((c) => c.url === "/auth/logout");
    expect(logout).toEqual({
      method: "POST",
      url: "/auth/logout",
      csrf: ME.csrf_token,
    });
  });

  it("leads admins to the fleet from the env badge and the account menu", async () => {
    renderHeader(ADMIN);

    expect(
      await screen.findByRole("link", {
        name: "Environment dev: sealing works. Open the fleet",
      }),
    ).toHaveAttribute("href", "/fleet");

    fireEvent.keyDown(
      screen.getByRole("button", { name: /account menu for octocat/i }),
      { key: "Enter" },
    );
    expect(
      await screen.findByRole("menuitem", { name: /fleet/i }),
    ).toHaveAttribute("href", "/fleet");
  });
});

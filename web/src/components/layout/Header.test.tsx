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
import { AuthProvider } from "@/lib/auth";
import { ThemeProvider } from "@/lib/theme-provider";
import { Header } from "./Header";
import { ME, fakeApi } from "@/test/fake-api";

describe("Header", () => {
  const originalAdapter = apiClient.defaults.adapter;
  const originalAssign = navigation.assign;

  afterEach(() => {
    apiClient.defaults.adapter = originalAdapter;
    navigation.assign = originalAssign;
  });

  it("shows the env and signs out with the CSRF token", async () => {
    const api = fakeApi({ me: ME });
    apiClient.defaults.adapter = api.adapter;
    const assign = vi.fn();
    navigation.assign = assign;
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });

    // the header's navigation links need a router
    const router = createRouter({
      routeTree: createRootRoute({
        component: () => (
          <AuthProvider>
            <Header />
          </AuthProvider>
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

    const trigger = await screen.findByRole("button", {
      name: /account menu for octocat/i,
    });
    expect(screen.getByLabelText("Environment dev")).toHaveTextContent("dev");

    fireEvent.keyDown(trigger, { key: "Enter" });
    fireEvent.click(await screen.findByRole("menuitem", { name: /sign out/i }));

    await waitFor(() => expect(assign).toHaveBeenCalledWith("/login"));
    const logout = api.calls.find((c) => c.url === "/auth/logout");
    expect(logout).toEqual({
      method: "POST",
      url: "/auth/logout",
      csrf: ME.csrf_token,
    });
  });
});

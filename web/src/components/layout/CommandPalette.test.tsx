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
import type { MeResponse } from "@/api/types";
import {
  ADMIN,
  ME,
  REPO_APPS,
  REPO_PLATFORM,
  SESSION,
  fakeApi,
} from "@/test/fake-api";

function renderAt(path: string, me: MeResponse = ME) {
  apiClient.defaults.adapter = fakeApi({
    me,
    repos: [REPO_APPS, REPO_PLATFORM],
    sessions: { "example-org/apps": { ...SESSION, pending_changes: 2 } },
  }).adapter;
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

describe("command palette", () => {
  const originalAdapter = apiClient.defaults.adapter;
  afterEach(() => {
    apiClient.defaults.adapter = originalAdapter;
  });

  it("opens with Ctrl+K and jumps to a repository", async () => {
    const router = renderAt("/secrets");
    await screen.findByRole("button", { name: /account menu/i });

    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    const dialog = await screen.findByRole("dialog", {
      name: "Search repositories and pages",
    });
    const apps = await within(dialog).findByRole("option", {
      name: /example-org\/apps/,
    });
    expect(apps).toHaveTextContent("2 Pending");
    expect(
      within(dialog).getByRole("option", { name: /example-org\/platform/ }),
    ).toHaveTextContent("Read Only");

    const input = within(dialog).getByRole("combobox");
    fireEvent.change(input, { target: { value: "platform" } });
    await waitFor(() =>
      expect(
        within(dialog).queryByRole("option", { name: /example-org\/apps/ }),
      ).not.toBeInTheDocument(),
    );
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() =>
      expect(router.state.location.pathname).toBe(
        "/dev/secrets/example-org/platform",
      ),
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("opens from the header and goes to a page", async () => {
    const router = renderAt("/secrets", ADMIN);
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Search repositories and pages",
      }),
    );
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("option", { name: /^fleet/i }));
    await waitFor(() =>
      expect(router.state.location.pathname).toBe("/dev/fleet"),
    );
  });

  it("says what found nothing", async () => {
    renderAt("/secrets");
    fireEvent.keyDown(
      await screen.findByRole("button", { name: /account menu/i }),
      { key: "k", ctrlKey: true },
    );
    const dialog = await screen.findByRole("dialog");
    await within(dialog).findByRole("option", { name: /example-org\/apps/ });
    fireEvent.change(within(dialog).getByRole("combobox"), {
      target: { value: "zzz" },
    });
    expect(
      await within(dialog).findByText("No repository or page matches “zzz”."),
    ).toBeInTheDocument();
  });

  it("offers the fleet and resealing to admins only", async () => {
    renderAt("/secrets");
    fireEvent.keyDown(
      await screen.findByRole("button", { name: /account menu/i }),
      { key: "k", ctrlKey: true },
    );
    const dialog = await screen.findByRole("dialog");
    expect(
      within(dialog).getByRole("option", { name: /^secrets/i }),
    ).toBeInTheDocument();
    expect(
      within(dialog).queryByRole("option", { name: /^fleet/i }),
    ).not.toBeInTheDocument();
    expect(
      within(dialog).queryByRole("option", { name: /^reseal/i }),
    ).not.toBeInTheDocument();
  });

  it("goes to resealing, found by what it is for", async () => {
    const router = renderAt("/secrets", ADMIN);
    fireEvent.keyDown(
      await screen.findByRole("button", { name: /account menu/i }),
      { key: "k", ctrlKey: true },
    );
    const dialog = await screen.findByRole("dialog");
    const input = within(dialog).getByRole("combobox");
    fireEvent.change(input, { target: { value: "schedules" } });
    await waitFor(() =>
      expect(
        within(dialog).queryByRole("option", { name: /^fleet/i }),
      ).not.toBeInTheDocument(),
    );
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() =>
      expect(router.state.location.pathname).toBe("/dev/reseal"),
    );
  });
});

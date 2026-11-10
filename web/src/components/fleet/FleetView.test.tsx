import { describe, it, expect, afterEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import apiClient from "@/api/client";
import type { Fleet } from "@/api/types";
import { FleetView } from "./FleetView";
import { ADMIN, KEY_A, KEY_B, agent, fakeApi } from "@/test/fake-api";

function renderFleet(fleet: Fleet | null, fleetStatus?: number) {
  apiClient.defaults.adapter = fakeApi({
    me: ADMIN,
    fleet,
    fleetStatus,
  }).adapter;
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <FleetView />
    </QueryClientProvider>,
  );
}

function row(name: string) {
  return screen.getByRole("rowheader", { name }).closest("tr") as HTMLElement;
}

describe("FleetView", () => {
  const originalAdapter = apiClient.defaults.adapter;
  afterEach(() => {
    apiClient.defaults.adapter = originalAdapter;
  });

  it("shows the env key when keys are in sync", async () => {
    renderFleet({
      env: "dev",
      env_key: KEY_A,
      keys_in_sync: true,
      agents: [
        agent({ id: "use1-blue" }),
        agent({ id: "use2-blue", region: "use2" }),
      ],
    });

    const banner = await screen.findByRole("region", {
      name: /environment key/i,
    });
    expect(within(banner).getByText("dev")).toBeInTheDocument();
    const fp = within(banner).getByTitle(KEY_A.fingerprint);
    expect(fp).toHaveTextContent("SHA256:AAAAaaaaBBBB…");
    expect(
      within(banner).getByRole("button", { name: /copy env key fingerprint/i }),
    ).toBeInTheDocument();
    expect(screen.queryByText(/keys out of sync/i)).not.toBeInTheDocument();
    expect(screen.getAllByRole("row")).toHaveLength(3); // header + 2 agents
  });

  it("warns when keys are out of sync and shows missing keys per agent", async () => {
    renderFleet({
      env: "dev",
      env_key: null,
      keys_in_sync: false,
      agents: [
        agent({
          id: "use1-blue",
          keys: [KEY_A],
          missing_keys: [KEY_B.fingerprint],
        }),
        agent({
          id: "use1-green",
          keys: [KEY_B],
          missing_keys: [KEY_A.fingerprint],
          controller: {
            namespace: "sealed-secrets",
            name: "sealed-secrets-controller",
            active_fingerprint: KEY_B.fingerprint,
          },
        }),
      ],
    });

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/keys out of sync/i);
    expect(
      within(row("use1-blue")).getByTitle(KEY_B.fingerprint),
    ).toHaveTextContent("1");
  });

  it("marks agents that never checked in and unhealthy agents", async () => {
    renderFleet({
      env: "prod",
      env_key: KEY_A,
      keys_in_sync: true,
      agents: [
        agent({ id: "use1-blue" }),
        agent({
          id: "use1-green",
          healthy: false,
          last_checkin: new Date(Date.now() - 10 * 60_000).toISOString(),
          issues: ["has not checked in recently"],
        }),
        agent({
          id: "use2-blue",
          region: "use2",
          checked_in: false,
          healthy: false,
          in_scope: false,
          last_checkin: undefined,
          agent_version: undefined,
          capabilities: undefined,
          controller: undefined,
          keys: undefined,
          keys_complete: false,
          missing_keys: undefined,
          issues: ["has never checked in"],
        }),
      ],
    });

    await screen.findByRole("region", { name: /environment key/i });
    expect(within(row("use1-blue")).getByText("Healthy")).toBeInTheDocument();
    expect(
      within(row("use1-green")).getByText("Unhealthy"),
    ).toBeInTheDocument();
    expect(within(row("use1-green")).getByText("10m ago")).toBeInTheDocument();
    expect(
      within(row("use1-green")).getByText("has not checked in recently"),
    ).toBeInTheDocument();
    const never = row("use2-blue");
    expect(within(never).getByText("Never checked in")).toBeInTheDocument();
    expect(within(never).getByText("has never checked in")).toBeInTheDocument();
    // registered capabilities still show for an agent that never checked in
    expect(within(never).getByText("seal")).toBeInTheDocument();
  });

  it("flags agents that report only their active key", async () => {
    renderFleet({
      env: "dev",
      env_key: KEY_A,
      keys_in_sync: true,
      agents: [agent({ id: "use1-blue", keys_complete: false })],
    });
    await screen.findByRole("region", { name: /environment key/i });
    expect(
      within(row("use1-blue")).getByText("(active only)"),
    ).toBeInTheDocument();
  });

  it("shows an empty state without agents", async () => {
    renderFleet({
      env: "dev",
      env_key: null,
      keys_in_sync: false,
      agents: null,
    });
    expect(
      await screen.findByText(/no agents registered/i),
    ).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("shows a load error", async () => {
    renderFleet(null, 500);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /could not load the fleet: the server encountered an error/i,
    );
  });
});

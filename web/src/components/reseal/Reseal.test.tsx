import { describe, it, expect, afterEach } from "vitest";
import {
  act,
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
import { AxiosError, type AxiosAdapter } from "axios";
import apiClient from "@/api/client";
import { ThemeProvider } from "@/lib/theme-provider";
import { routeTree } from "@/routeTree.gen";
import {
  ADMIN,
  KEY_A,
  KEY_B,
  ME,
  STATUS,
  fakeApi,
  iso,
  resealPullRequest,
  resealRun,
  resealSchedule,
  type ResealFixtures,
} from "@/test/fake-api";
import { formatDate, firstRunAt } from "./format";

const DAY = 86_400_000;

function renderAt(
  path: string,
  opts: Partial<Parameters<typeof fakeApi>[0]> = {},
  /** Stands between the page and the fake, to fail or slow a request. */
  wrap: (adapter: AxiosAdapter) => AxiosAdapter = (a) => a,
) {
  const api = fakeApi({ me: ADMIN, ...opts });
  apiClient.defaults.adapter = wrap(api.adapter);
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
  return { api, router, queryClient };
}

const PAGE = "/dev/reseal";

/**
 * Renders the reseal page as an admin with these fixtures, once its
 * sections are on screen.
 */
async function renderReseal(
  reseal: ResealFixtures = {},
  opts: Partial<Parameters<typeof fakeApi>[0]> = {},
  path = PAGE,
  wrap?: (adapter: AxiosAdapter) => AxiosAdapter,
) {
  const rendered = renderAt(path, { reseal, ...opts }, wrap);
  await screen.findByRole("heading", { level: 1, name: "Reseal" });
  return rendered;
}

function section(name: RegExp | string) {
  return screen.getByRole("region", { name });
}

/** A table's row by the text of its row header. */
function rowOf(table: HTMLElement, name: string | RegExp) {
  return within(table)
    .getByRole("rowheader", { name })
    .closest("tr") as HTMLElement;
}

/** "enabled", or the reason a grayed-out button gives. */
function availability(button: HTMLElement): string {
  if (button.getAttribute("aria-disabled") !== "true") return "enabled";
  const id = (button.getAttribute("aria-describedby") ?? "").split(" ")[0]!;
  return document.getElementById(id)?.textContent ?? "no reason";
}

describe("reseal page access", () => {
  const originalAdapter = apiClient.defaults.adapter;
  afterEach(() => {
    apiClient.defaults.adapter = originalAdapter;
  });

  it("tells people who are not admins that resealing is for admins", async () => {
    const { api } = renderAt(PAGE, { me: ME });
    expect(
      await screen.findByRole("heading", {
        level: 1,
        name: "Resealing is for admins",
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Back to Secrets" }),
    ).toHaveAttribute("href", "/dev/secrets");
    // nothing about resealing was asked for
    expect(api.calls.filter((c) => c.url.startsWith("/reseal/"))).toEqual([]);
    // and the navigation offers it to admins only
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(
      within(nav).queryByRole("link", { name: "Reseal" }),
    ).not.toBeInTheDocument();
  });

  it("shows admins the page, pull requests first, marked as the current page", async () => {
    await renderReseal();
    expect(
      await screen.findByRole("heading", { level: 1, name: "Reseal" }),
    ).toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).getByRole("link", { name: "Reseal" })).toHaveAttribute(
      "aria-current",
      "page",
    );
    // what resealing does and does not do, once, at the top
    const note = screen.getByLabelText("What resealing does");
    expect(note).toHaveTextContent(
      /re-encrypts values sealed with older keys for the env key/,
    );
    expect(note).toHaveTextContent(/doesn't rotate values/);
    expect(within(note).getByRole("link", { name: "fleet" })).toHaveAttribute(
      "href",
      "/dev/fleet",
    );
    const headings = screen
      .getAllByRole("heading", { level: 2 })
      .map((h) => h.textContent);
    expect(headings).toEqual(["Reseal pull requests", "Schedules", "Runs"]);
    expect(
      screen.queryByText(/can't be resealed in dev/),
    ).not.toBeInTheDocument();
  });

  it("warns when the env can't reseal, and says why", async () => {
    await renderReseal(
      { schedules: [resealSchedule({ id: "sch-apps" })] },
      {
        status: {
          ...STATUS,
          can_reseal: false,
          reseal_blocked: "no agent has the reseal capability",
        },
      },
    );
    const alert = (
      await screen.findByText("Values can't be resealed in dev right now")
    ).closest("[role=status]") as HTMLElement;
    expect(alert).toHaveTextContent(/No agent has the reseal capability\./);
    // Run now says the same where it is grayed out
    const runNow = await screen.findByRole("button", { name: "Run Apps now" });
    expect(availability(runNow)).toBe("No agent has the reseal capability.");
  });
});

describe("reseal pull requests", () => {
  const originalAdapter = apiClient.defaults.adapter;
  afterEach(() => {
    apiClient.defaults.adapter = originalAdapter;
  });

  const OPEN_OLD = resealPullRequest({
    number: 12,
    repo: "example-org/platform",
    opened_at: iso(9 * DAY),
    from_keys: [KEY_A.fingerprint, KEY_B.fingerprint, "SHA256:CCCCcccc"],
  });
  const OPEN_NEW = resealPullRequest({
    number: 14,
    source: "session",
    schedule_id: undefined,
    schedule_name: undefined,
    run_id: undefined,
    requested_by: "bob",
    title: "Seal 1 value and reseal 2 for dev",
    values: 2,
    files: 1,
  });
  const MERGED = resealPullRequest({
    number: 9,
    state: "merged",
    opened_at: iso(20 * DAY),
    merged_at: iso(15 * DAY),
  });
  const CLOSED = resealPullRequest({
    number: 7,
    state: "closed",
    opened_at: iso(30 * DAY),
    closed_at: iso(25 * DAY),
  });
  const ALL = [OPEN_NEW, MERGED, OPEN_OLD, CLOSED];

  it("lists the open ones by default, oldest first, with what each moves", async () => {
    const { api } = await renderReseal({ pullRequests: ALL });
    const table = await within(section("Reseal pull requests")).findByRole(
      "table",
      { name: "Reseal pull requests" },
    );
    expect(
      api.calls.find((c) => c.url === "/reseal/pull-requests")?.params,
    ).toEqual({ state: "open" });
    expect(
      within(table)
        .getAllByRole("rowheader")
        .map((h) => h.textContent),
    ).toEqual(["example-org/platform", "example-org/apps"]);
    expect(
      within(section("Reseal pull requests")).getByText("2 open"),
    ).toBeVisible();

    const old = rowOf(table, "example-org/platform");
    // the pull request links out
    const link = within(old).getByRole("link", { name: /#12/ });
    expect(link).toHaveAttribute(
      "href",
      "https://github.com/example-org/platform/pull/12",
    );
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveTextContent("#12 Reseal 3 values in 2 files for dev");
    // its source is the schedule, which opens its run
    expect(
      within(old).getByRole("link", { name: "Apps: show its run" }),
    ).toHaveAttribute("href", "/dev/reseal?schedule=sch-apps&run=run-1");
    expect(old).toHaveTextContent("3 valuesin 2 files");
    // the keys it moves values off, short, two then a count
    expect(within(old).getByTitle(KEY_A.fingerprint)).toHaveTextContent(
      "SHA256:AAAAaaaaBBBB…",
    );
    expect(within(old).getByText("and 1 more")).toBeVisible();
    // open a long time: its age in the warning color
    expect(within(old).getByText("open 9 days")).toHaveClass("text-warning");
    expect(within(old).getByText("Open")).toBeVisible();
    expect(within(old).getByTitle(/^State read from GitHub/)).toHaveTextContent(
      "5m ago",
    );

    // a session's pull request names the user who opened it
    const fresh = rowOf(table, "example-org/apps");
    expect(fresh).toHaveTextContent(/bobSession/);
    expect(
      within(fresh).queryByText(/^open \d+ days$/),
    ).not.toBeInTheDocument();
  });

  it("shows merged, closed and all with the filter", async () => {
    const { api } = await renderReseal({ pullRequests: ALL });
    const prs = section("Reseal pull requests");
    await within(prs).findByRole("table");
    const filter = within(prs).getByRole("group", {
      name: "Pull requests to show",
    });
    expect(
      within(filter).getByRole("button", { name: "Open" }),
    ).toHaveAttribute("aria-pressed", "true");

    fireEvent.click(within(filter).getByRole("button", { name: "Merged" }));
    await within(prs).findByText("1 merged");
    let table = within(prs).getByRole("table");
    const merged = rowOf(table, "example-org/apps");
    expect(within(merged).getByText("Merged")).toBeVisible();
    expect(within(merged).getByTitle(/^Merged /)).toHaveTextContent("15d ago");
    expect(api.calls.at(-1)?.params).toEqual({ state: "merged" });

    fireEvent.click(within(filter).getByRole("button", { name: "Closed" }));
    await within(prs).findByText("1 closed");
    table = within(prs).getByRole("table");
    expect(within(table).getByText("Closed")).toBeVisible();

    fireEvent.click(within(filter).getByRole("button", { name: "All" }));
    await within(prs).findByText("4 pull requests");
    table = within(prs).getByRole("table");
    // newest first once they are not a queue
    expect(
      within(table)
        .getAllByRole("link", { name: /^#\d+/ })
        .map((l) => l.textContent?.split(" ")[0]),
    ).toEqual(["#14", "#12", "#9", "#7"]);
  });

  it("counts those in repositories the viewer can't read", async () => {
    await renderReseal({ pullRequests: [OPEN_NEW], hidden: 2 });
    const prs = section("Reseal pull requests");
    await within(prs).findByRole("table");
    expect(
      within(prs).getByText("2 more are in repositories you can't read."),
    ).toBeVisible();
  });

  it("says when there are none, and when some are hidden", async () => {
    await renderReseal({ pullRequests: [MERGED], hidden: 1 });
    const prs = section("Reseal pull requests");
    expect(
      await within(prs).findByText("No open reseal pull requests"),
    ).toBeVisible();
    expect(prs).toHaveTextContent(
      "1 is in a repository you can't read, so it isn't listed.",
    );
  });

  it("opens a pull request's run from its source", async () => {
    const { router } = await renderReseal({
      pullRequests: [OPEN_OLD],
      schedules: [resealSchedule({ id: "sch-apps" })],
      runs: [resealRun({ id: "run-1" }), resealRun({ id: "run-0" })],
    });
    fireEvent.click(
      await screen.findByRole("link", { name: "Apps: show its run" }),
    );
    await waitFor(() =>
      expect(router.state.location.search).toEqual({
        schedule: "sch-apps",
        run: "run-1",
      }),
    );
    const runs = section("Runs");
    await waitFor(() =>
      expect(
        within(runs).getAllByRole("button", { expanded: true }),
      ).toHaveLength(1),
    );
  });
});

describe("reseal schedules", () => {
  const originalAdapter = apiClient.defaults.adapter;
  afterEach(() => {
    apiClient.defaults.adapter = originalAdapter;
  });

  const APPS = resealSchedule({
    id: "sch-apps",
    last_run: resealRun({ id: "run-1" }),
  });
  const WIDE = resealSchedule({
    id: "sch-wide",
    name: "Everything",
    repos: ["example-org/apps", "example-org/platform", "example-org/billing"],
    orgs: ["example-org"],
    interval_days: 30,
    enabled: false,
    next_run_at: null,
  });

  async function schedulesTable() {
    return within(section("Schedules")).findByRole("table", {
      name: "Reseal schedules",
    });
  }

  it("lists each schedule's scope, interval, next and last run", async () => {
    await renderReseal({ schedules: [APPS, WIDE] });
    const table = await schedulesTable();
    expect(
      within(section("Schedules")).getByText("2 schedules, 1 paused"),
    ).toBeVisible();

    const apps = rowOf(table, /^Apps/);
    expect(apps).toHaveTextContent("by alice");
    expect(within(apps).getByText("example-org/apps")).toBeVisible();
    expect(apps).toHaveTextContent("75 days≈ 2½ months");
    expect(within(apps).getByTitle(/^Next run /)).toHaveTextContent("in 40d");
    expect(within(apps).getByText("Succeeded")).toBeVisible();
    expect(
      within(apps).getByRole("link", { name: /^Show the latest run of Apps/ }),
    ).toHaveAttribute("href", "/dev/reseal?schedule=sch-apps&run=run-1");

    // orgs first, three chips, then the rest as a count
    const wide = rowOf(table, /^Everything/);
    expect(
      within(wide).getByTitle("Every repository of example-org"),
    ).toBeVisible();
    expect(within(wide).getByText("+1")).toHaveAttribute(
      "title",
      "example-org/billing",
    );
    expect(within(wide).getByText("Paused")).toBeVisible();
    expect(within(wide).getByText("Never run")).toBeVisible();
    // the same actions, in the same order, on every row
    expect(
      within(wide)
        .getAllByRole("button")
        .map((b) => b.getAttribute("aria-label")),
    ).toEqual([
      "Run Everything now",
      "Edit Everything",
      "Resume Everything",
      "Delete Everything",
    ]);
  });

  it("creates a schedule, with chips for its repositories and orgs", async () => {
    const { api } = await renderReseal({ schedules: [] });
    expect(
      await within(section("Schedules")).findByText("No schedules"),
    ).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "New schedule" }));
    const dialog = await screen.findByRole("dialog", { name: "New schedule" });
    const name = within(dialog).getByLabelText("Name");
    const repos = within(dialog).getByLabelText("Repositories");
    const orgs = within(dialog).getByLabelText("Orgs");
    const days = within(dialog).getByLabelText("Every");

    fireEvent.change(name, { target: { value: "Platform" } });
    // Enter moves on from the name
    fireEvent.keyDown(name, { key: "Enter" });
    expect(repos).toHaveFocus();
    fireEvent.change(repos, { target: { value: "example-org/apps" } });
    fireEvent.keyDown(repos, { key: "Enter" });
    expect(within(dialog).getByText("example-org/apps")).toBeVisible();
    // a pasted list becomes several chips
    fireEvent.change(repos, {
      target: { value: "example-org/platform, example-org/billing" },
    });
    fireEvent.keyDown(repos, { key: "Enter" });
    expect(
      within(dialog).getByRole("button", {
        name: "Remove example-org/billing",
      }),
    ).toBeVisible();
    fireEvent.click(
      within(dialog).getByRole("button", {
        name: "Remove example-org/billing",
      }),
    );
    // an empty field's Enter moves on too
    fireEvent.keyDown(repos, { key: "Enter" });
    expect(orgs).toHaveFocus();
    fireEvent.change(orgs, { target: { value: "example-org" } });
    fireEvent.keyDown(orgs, { key: "," });

    // the interval reads in months, and the first run in a date
    expect(dialog).toHaveTextContent("75 days ≈ 2½ months");
    fireEvent.change(days, { target: { value: "14" } });
    expect(dialog).toHaveTextContent("14 days = 2 weeks");
    expect(dialog).toHaveTextContent(
      `First run in 14 days, on ${formatDate(firstRunAt(14, new Date()))}.`,
    );
    fireEvent.click(within(dialog).getByLabelText("Enabled"));
    expect(dialog).toHaveTextContent(
      "Paused: it doesn't run until you resume it.",
    );
    fireEvent.click(within(dialog).getByLabelText("Enabled"));

    // ⌘/Ctrl+Enter saves from any field
    fireEvent.keyDown(days, { key: "Enter", ctrlKey: true });
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    const post = api.calls.find(
      (c) => c.method === "POST" && c.url === "/reseal/schedules",
    );
    expect(post?.csrf).toBe(ADMIN.csrf_token);
    expect(post?.body).toEqual({
      name: "Platform",
      repos: ["example-org/apps", "example-org/platform"],
      orgs: ["example-org"],
      interval_days: 14,
      enabled: true,
    });
    const table = await schedulesTable();
    expect(rowOf(table, /^Platform/)).toHaveTextContent("in 14d");
    expect(await screen.findByText("Created Platform")).toBeVisible();
  });

  it("says what is wrong before sending, and sends nothing", async () => {
    const { api } = await renderReseal({ schedules: [] });
    await screen.findByText("No schedules");
    fireEvent.click(screen.getByRole("button", { name: "New schedule" }));
    const dialog = await screen.findByRole("dialog", { name: "New schedule" });
    const repos = within(dialog).getByLabelText("Repositories");
    // a repository that is not owner/name stays typed, with why
    fireEvent.change(repos, { target: { value: "apps" } });
    fireEvent.keyDown(repos, { key: "Enter" });
    expect(repos).toHaveValue("apps");
    expect(repos).toHaveAttribute("aria-invalid", "true");
    expect(repos).toHaveAccessibleDescription(
      "Use owner/name, as in example-org/apps.",
    );
    fireEvent.change(repos, { target: { value: "" } });
    fireEvent.change(within(dialog).getByLabelText("Every"), {
      target: { value: "400" },
    });

    fireEvent.click(
      within(dialog).getByRole("button", { name: "Create schedule" }),
    );
    expect(within(dialog).getByText("Name the schedule.")).toBeVisible();
    expect(
      within(dialog).getByText("Add a repository or an org."),
    ).toBeVisible();
    expect(
      within(dialog).getByText("Use a whole number of days from 1 to 365."),
    ).toBeVisible();
    expect(within(dialog).getByLabelText("Name")).toHaveFocus();
    // a duplicate is refused as it is added
    fireEvent.change(repos, { target: { value: "example-org/apps" } });
    fireEvent.keyDown(repos, { key: "Enter" });
    fireEvent.change(repos, { target: { value: "Example-Org/Apps" } });
    fireEvent.keyDown(repos, { key: "Enter" });
    expect(repos).toHaveAccessibleDescription(
      "Example-Org/Apps is already added.",
    );
    expect(
      api.calls.filter(
        (c) => c.method === "POST" && c.url.startsWith("/reseal"),
      ),
    ).toEqual([]);
  });

  it("shows the control plane's refusal and keeps what was typed", async () => {
    await renderReseal({
      schedules: [],
      scheduleError: {
        status: 409,
        error: "an env has at most 50 schedules",
      },
    });
    await screen.findByText("No schedules");
    fireEvent.click(screen.getByRole("button", { name: "New schedule" }));
    const dialog = await screen.findByRole("dialog", { name: "New schedule" });
    fireEvent.change(within(dialog).getByLabelText("Name"), {
      target: { value: "Platform" },
    });
    fireEvent.change(within(dialog).getByLabelText("Orgs"), {
      target: { value: "example-org" },
    });
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Create schedule" }),
    );
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "Could not create the schedule: An env has at most 50 schedules.",
    );
    expect(within(dialog).getByLabelText("Name")).toHaveValue("Platform");
    expect(within(dialog).getByText("example-org")).toBeVisible();
  });

  it("refuses a 400 with the control plane's sentence", async () => {
    await renderReseal({
      schedules: [APPS],
      scheduleError: {
        status: 400,
        error:
          "repository example-org/gone is not one the GitHub App can reach",
      },
    });
    fireEvent.click(await screen.findByRole("button", { name: "Edit Apps" }));
    const dialog = await screen.findByRole("dialog", { name: "Edit schedule" });
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Remove example-org/apps" }),
    );
    const repos = within(dialog).getByLabelText("Repositories");
    fireEvent.change(repos, { target: { value: "example-org/gone" } });
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Save changes" }),
    );
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "Could not save the schedule: Repository example-org/gone is not one the GitHub App can reach.",
    );
  });

  it("edits a schedule, sending only what changed", async () => {
    const { api } = await renderReseal({ schedules: [APPS] });
    fireEvent.click(await screen.findByRole("button", { name: "Edit Apps" }));
    const dialog = await screen.findByRole("dialog", { name: "Edit schedule" });
    expect(within(dialog).getByLabelText("Name")).toHaveValue("Apps");
    expect(within(dialog).getByLabelText("Every")).toHaveValue(75);
    // its next run stays while its interval does
    expect(dialog).toHaveTextContent(/Next run in 40d, on /);
    fireEvent.change(within(dialog).getByLabelText("Every"), {
      target: { value: "90" },
    });
    expect(dialog).toHaveTextContent("90 days ≈ 3 months");
    expect(dialog).toHaveTextContent(/Next run in 90 days, on /);
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Save changes" }),
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    const patch = api.calls.find((c) => c.method === "PATCH");
    expect(patch?.url).toBe("/reseal/schedules/sch-apps");
    expect(patch?.body).toEqual({ interval_days: 90 });
    const table = await schedulesTable();
    await waitFor(() =>
      expect(rowOf(table, /^Apps/)).toHaveTextContent("90 days"),
    );
  });

  it("pauses and resumes a schedule", async () => {
    const { api } = await renderReseal({ schedules: [APPS] });
    fireEvent.click(await screen.findByRole("button", { name: "Pause Apps" }));
    expect(await screen.findByText("Paused Apps")).toBeVisible();
    const table = await schedulesTable();
    await waitFor(() =>
      expect(within(rowOf(table, /^Apps/)).getByText("Paused")).toBeVisible(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Resume Apps" }));
    expect(await screen.findByText("Resumed Apps")).toBeVisible();
    expect(
      api.calls.filter((c) => c.method === "PATCH").map((c) => c.body),
    ).toEqual([{ enabled: false }, { enabled: true }]);
  });

  it("deletes a schedule after confirming, cancelling its run", async () => {
    const { api } = await renderReseal({
      schedules: [{ ...APPS, active_run_id: "run-2" }],
      runs: [
        resealRun({ id: "run-2", status: "running", finished_at: undefined }),
      ],
    });
    fireEvent.click(await screen.findByRole("button", { name: "Delete Apps" }));
    const dialog = await screen.findByRole("dialog", {
      name: "Delete this schedule?",
    });
    expect(dialog).toHaveTextContent("Its run in progress is cancelled.");
    expect(dialog).toHaveTextContent(/Pull requests its runs opened stay open/);
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Delete schedule" }),
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(api.calls.find((c) => c.method === "DELETE")?.url).toBe(
      "/reseal/schedules/sch-apps",
    );
    expect(
      await within(section("Schedules")).findByText("No schedules"),
    ).toBeVisible();
    // its run shows as cancelled
    expect(
      await within(document.getElementById("run-run-2")!).findByText(
        "Cancelled",
      ),
    ).toBeVisible();
  });

  it("starts a run now, then grays Run now out while it runs", async () => {
    const { api } = await renderReseal({ schedules: [APPS], runs: [] });
    const runNow = await screen.findByRole("button", { name: "Run Apps now" });
    expect(availability(runNow)).toBe("enabled");
    fireEvent.click(runNow);
    expect(await screen.findByText("Started a run of Apps")).toBeVisible();
    expect(
      api.calls.find((c) => c.method === "POST" && c.url.endsWith("/run"))?.url,
    ).toBe("/reseal/schedules/sch-apps/run");
    await waitFor(() =>
      expect(
        availability(screen.getByRole("button", { name: "Run Apps now" })),
      ).toBe(
        "A run is in progress. Wait for it to finish, or cancel it under Runs.",
      ),
    );
    // the run shows under Runs, by whom
    const runs = section("Runs");
    const row = await within(runs).findByRole("rowheader", { name: "Apps" });
    expect(row.closest("tr")).toHaveTextContent(/QueuedRun nowby octocat/);
  });

  it("says why a run could not start", async () => {
    await renderReseal({
      schedules: [APPS],
      runError: {
        status: 409,
        error: "a run of this schedule is already in progress",
      },
    });
    fireEvent.click(
      await screen.findByRole("button", { name: "Run Apps now" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Could not start a run of Apps: A run of this schedule is already in progress.",
    );
    fireEvent.click(screen.getByRole("button", { name: "Dismiss" }));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("grays out New schedule at the limit, with why", async () => {
    await renderReseal({
      schedules: Array.from({ length: 50 }, (_, i) =>
        resealSchedule({ id: `sch-${i}`, name: `Schedule ${i}` }),
      ),
    });
    await schedulesTable();
    expect(
      availability(screen.getByRole("button", { name: "New schedule" })),
    ).toBe("An env has at most 50 schedules. Delete one first.");
  });
});

describe("reseal runs", () => {
  const originalAdapter = apiClient.defaults.adapter;
  afterEach(() => {
    apiClient.defaults.adapter = originalAdapter;
  });

  const RUNNING = resealRun({
    id: "run-6",
    status: "running",
    trigger: "manual",
    requested_by: "bob",
    started_at: iso(90_000),
    finished_at: undefined,
    repos: { total: 10, done: 4, hidden: 1 },
    values: { resealed: 5, current: 20, failed: 1 },
    pull_requests: 2,
  });
  const STATUSES = [
    RUNNING,
    resealRun({ id: "run-5", status: "queued", finished_at: undefined }),
    resealRun({ id: "run-4", status: "partial" }),
    resealRun({
      id: "run-3",
      status: "failed",
      error: "the GitHub App cannot list the repositories of example-org",
    }),
    resealRun({ id: "run-2", status: "cancelled" }),
    resealRun({ id: "run-1" }),
  ];

  function runRow(id: string) {
    return document.getElementById(`run-${id}`) as HTMLElement;
  }

  it("shows each run's status, trigger, duration, repositories, values and pull requests", async () => {
    const { api } = await renderReseal({ runs: STATUSES });
    const runs = section("Runs");
    await within(runs).findByRole("table");
    expect(within(runs).getByText("6 runs, 2 running")).toBeVisible();
    expect(api.calls.find((c) => c.url === "/reseal/runs")?.params).toEqual({
      limit: 25,
    });
    // each status is a word in its badge, in the status column
    expect(
      STATUSES.map(
        (r) =>
          runRow(r.id).querySelector("td")?.firstElementChild?.firstChild
            ?.textContent,
      ),
    ).toEqual([
      "Running",
      "Queued",
      "Partial",
      "Failed",
      "Cancelled",
      "Succeeded",
    ]);

    const running = runRow("run-6");
    expect(running).toHaveTextContent("Run nowby bob");
    expect(running).toHaveTextContent("1m 30s so far");
    expect(running).toHaveTextContent("5 resealed20 current1 failed");
    expect(within(running).getByText("1 failed")).toHaveClass(
      "text-destructive",
    );
    // progress, with one repository the viewer can't read
    const bar = within(running).getByRole("progressbar");
    expect(bar).toHaveAttribute("aria-valuenow", "4");
    expect(bar).toHaveAttribute("aria-valuemax", "10");
    expect(within(running).getByText("4 of 10").parentElement).toHaveAttribute(
      "title",
      "1 of them is in repositories you can't read",
    );

    const finished = runRow("run-1");
    expect(finished).toHaveTextContent("Scheduled");
    expect(finished).toHaveTextContent("4m 12s");
    expect(within(finished).queryByRole("progressbar")).not.toBeInTheDocument();
    expect(runRow("run-3")).toHaveTextContent(
      "The GitHub App cannot list the repositories of example-org.",
    );
  });

  it("cancels an active run after confirming, and only an active one", async () => {
    const { api } = await renderReseal({ runs: STATUSES });
    await within(section("Runs")).findByRole("table");
    expect(
      availability(
        within(runRow("run-1")).getByRole("button", {
          name: "Cancel the run of Apps",
        }),
      ),
    ).toBe("Only a queued or running run can be cancelled.");

    fireEvent.click(
      within(runRow("run-6")).getByRole("button", {
        name: "Cancel the run of Apps",
      }),
    );
    const dialog = await screen.findByRole("dialog", {
      name: "Cancel this run?",
    });
    expect(dialog).toHaveTextContent(
      "Pull requests it already opened stay open.",
    );
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel run" }));
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(api.calls.find((c) => c.url.endsWith("/cancel"))?.url).toBe(
      "/reseal/runs/run-6/cancel",
    );
    await waitFor(() =>
      expect(within(runRow("run-6")).getByText("Cancelled")).toBeVisible(),
    );
  });

  it("opens a run's repositories, with failures and those the viewer can't read", async () => {
    const { router } = await renderReseal({
      runs: STATUSES,
      details: {
        "run-6": {
          ...RUNNING,
          repositories: [
            {
              repo: "example-org/apps",
              status: "opened",
              files: 2,
              values: { resealed: 3, current: 10, failed: 0 },
              pull_request: {
                number: 12,
                url: "https://github.com/example-org/apps/pull/12",
              },
            },
            {
              repo: "example-org/platform",
              status: "skipped",
              files: 0,
              values: { resealed: 0, current: 0, failed: 0 },
              reason: "reseal pull request #9 is still open",
            },
            {
              repo: "example-org/billing",
              status: "failed",
              files: 1,
              values: { resealed: 2, current: 1, failed: 2 },
              reason: "1 value could not be resealed",
              failures: [
                {
                  path: "deploy/billing/sealed-secret.yaml",
                  key: "api-key",
                  document: 2,
                  region: "use2",
                  error: "no key in the cluster opens it",
                },
              ],
            },
            {
              repo: "example-org/web",
              status: "resealing",
              files: 3,
              values: { resealed: 0, current: 7, failed: 0 },
            },
          ],
        },
      },
    });
    await within(section("Runs")).findByRole("table");
    const toggle = within(runRow("run-6")).getByRole("button", {
      name: "Apps",
      expanded: false,
    });
    fireEvent.click(toggle);
    // the open run is in the URL, so a link opens it too
    await waitFor(() =>
      expect(router.state.location.search).toEqual({ run: "run-6" }),
    );
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    const repos = await screen.findByRole("table", {
      name: "Repositories in the run of Apps",
    });
    const opened = rowOf(repos, "example-org/apps");
    expect(within(opened).getByText("PR opened")).toBeVisible();
    expect(within(opened).getByRole("link", { name: /#12/ })).toHaveAttribute(
      "href",
      "https://github.com/example-org/apps/pull/12",
    );
    expect(opened).toHaveTextContent("3 resealed, 10 current");
    // skipped: no values, and why
    const skipped = rowOf(repos, "example-org/platform");
    expect(within(skipped).getByText("Skipped")).toBeVisible();
    expect(within(skipped).getAllByLabelText("none")).toHaveLength(2);
    expect(skipped).toHaveTextContent("Reseal pull request #9 is still open.");
    expect(
      within(rowOf(repos, "example-org/web")).getByText("Resealing"),
    ).toBeVisible();
    const failed = rowOf(repos, "example-org/billing");
    expect(failed).toHaveTextContent("Failed");
    expect(failed).toHaveTextContent("2 resealed, 1 current, 2 failed");

    const failures = screen.getByRole("table", {
      name: "Values that could not be resealed in example-org/billing",
    });
    const failure = rowOf(failures, "deploy/billing/sealed-secret.yaml");
    expect(failure).toHaveTextContent(
      "api-key#2use2No key in the cluster opens it.",
    );
    expect(
      screen.getByText("1 more value failed; only the first 1 are listed."),
    ).toBeVisible();
    expect(
      screen.getByText("1 more is a repository you can't read."),
    ).toBeVisible();

    // the same toggle closes it
    fireEvent.click(toggle);
    await waitFor(() =>
      expect(
        screen.queryByRole("table", {
          name: "Repositories in the run of Apps",
        }),
      ).not.toBeInTheDocument(),
    );
  });

  it("says when every repository of a run is hidden", async () => {
    await renderReseal(
      {
        runs: [
          resealRun({ id: "run-1", repos: { total: 2, done: 2, hidden: 2 } }),
        ],
      },
      {},
      `${PAGE}?run=run-1`,
    );
    expect(
      await screen.findByText(
        "All 2 of its repositories are ones you can't read.",
      ),
    ).toBeVisible();
  });

  it("lists one schedule's runs when it is picked", async () => {
    const { api, router } = await renderReseal({
      schedules: [
        resealSchedule({ id: "sch-apps" }),
        resealSchedule({ id: "sch-web", name: "Web" }),
      ],
      runs: [
        resealRun({
          id: "run-2",
          schedule_id: "sch-web",
          schedule_name: "Web",
        }),
        resealRun({ id: "run-1" }),
      ],
    });
    const runs = section("Runs");
    await within(runs).findByText("2 runs");
    fireEvent.change(within(runs).getByLabelText("Schedule"), {
      target: { value: "sch-web" },
    });
    await within(runs).findByText("1 run");
    expect(api.calls.at(-1)?.params).toEqual({
      schedule: "sch-web",
      limit: 25,
    });
    expect(router.state.location.search).toEqual({ schedule: "sch-web" });
    expect(within(runs).getByRole("rowheader", { name: "Web" })).toBeVisible();
  });

  it("says when there are no runs", async () => {
    await renderReseal({ runs: [] });
    expect(
      await within(section("Runs")).findByText("No runs yet"),
    ).toBeVisible();
  });
});

/** An error response from the control plane, as axios raises it. */
function httpError(
  config: Parameters<AxiosAdapter>[0],
  status: number,
  error: string,
): AxiosError {
  return new AxiosError("error", "ERR_BAD_RESPONSE", config, undefined, {
    status,
    statusText: "",
    data: { error },
    headers: {},
    config,
  } as never);
}

/** Holds back the GETs of `path` until `release` is called. */
function holdGets(path: string) {
  let held = false;
  const waiting: (() => void)[] = [];
  return {
    hold: () => {
      held = true;
    },
    release: () => {
      held = false;
      waiting.splice(0).forEach((go) => go());
    },
    wrap:
      (adapter: AxiosAdapter): AxiosAdapter =>
      async (config) => {
        const get = (config.method ?? "get").toLowerCase() === "get";
        if (held && get && (config.url ?? "").endsWith(path)) {
          await new Promise<void>((go) => waiting.push(go));
        }
        return adapter(config);
      },
  };
}

describe("reseal page, after review", () => {
  const originalAdapter = apiClient.defaults.adapter;
  afterEach(() => {
    apiClient.defaults.adapter = originalAdapter;
  });

  it("opens a pull request's run when it is older than the list's latest", async () => {
    const runs = Array.from({ length: 30 }, (_, i) =>
      resealRun({ id: `run-${30 - i}`, started_at: iso((i + 1) * DAY) }),
    );
    const { api, router } = await renderReseal({
      schedules: [resealSchedule({ id: "sch-apps" })],
      runs,
      pullRequests: [resealPullRequest({ number: 4, run_id: "run-1" })],
    });
    fireEvent.click(
      await screen.findByRole("link", { name: "Apps: show its run" }),
    );
    await waitFor(() =>
      expect(router.state.location.search).toMatchObject({ run: "run-1" }),
    );
    // read on its own, and shown open under the latest
    const row = await waitFor(() => {
      const r = document.getElementById("run-run-1");
      expect(r).not.toBeNull();
      return r as HTMLElement;
    });
    expect(api.calls.some((c) => c.url === "/reseal/runs/run-1")).toBe(true);
    expect(
      within(row).getByRole("button", { name: "Apps", expanded: true }),
    ).toBeVisible();
    expect(
      await screen.findByText("It found no repository in its scope."),
    ).toBeVisible();
  });

  it("says when a linked run is no longer kept", async () => {
    await renderReseal(
      { runs: [resealRun({ id: "run-2" })] },
      {},
      `${PAGE}?run=run-gone`,
    );
    expect(
      await screen.findByText(
        "The run this link opens isn't kept any more: runs are kept for 180 days after they finish.",
      ),
    ).toBeVisible();
  });

  it("says when the status can't be read, rather than checking for good", async () => {
    await renderReseal(
      { schedules: [resealSchedule({ id: "sch-apps" })] },
      {},
      PAGE,
      (adapter) => async (config) => {
        if ((config.url ?? "").endsWith("/status")) {
          throw httpError(config, 503, "the control plane is starting");
        }
        return adapter(config);
      },
    );
    expect(
      await screen.findByText(
        "Couldn't check whether values can be resealed in dev",
      ),
    ).toBeVisible();
    await waitFor(() =>
      expect(
        availability(screen.getByRole("button", { name: "Run Apps now" })),
      ).toBe(
        "Couldn't check whether values can be resealed: The control plane is starting. Trying again.",
      ),
    );
  });

  it("keeps Run now busy until the schedule shows its run", async () => {
    const schedules = holdGets("/reseal/schedules");
    const { api } = await renderReseal(
      { schedules: [resealSchedule({ id: "sch-apps" })], runs: [] },
      {},
      PAGE,
      schedules.wrap,
    );
    const runNow = await screen.findByRole("button", { name: "Run Apps now" });
    schedules.hold();
    fireEvent.click(runNow);
    await screen.findByText("Started a run of Apps");
    // the run started, but the list that says so is still on its way
    const again = screen.getByRole("button", { name: "Run Apps now" });
    expect(availability(again)).toBe("Starting a run…");
    fireEvent.click(again);
    schedules.release();
    await waitFor(() =>
      expect(
        availability(screen.getByRole("button", { name: "Run Apps now" })),
      ).toMatch(/^A run is in progress/),
    );
    expect(
      api.calls.filter((c) => c.method === "POST" && c.url.endsWith("/run")),
    ).toHaveLength(1);
  });

  it("keeps Cancel busy until the run shows as cancelled", async () => {
    const runs = holdGets("/reseal/runs");
    await renderReseal(
      {
        runs: [
          resealRun({ id: "run-6", status: "running", finished_at: undefined }),
        ],
      },
      {},
      PAGE,
      runs.wrap,
    );
    const row = await waitFor(() => {
      const r = document.getElementById("run-run-6");
      expect(r).not.toBeNull();
      return r as HTMLElement;
    });
    runs.hold();
    fireEvent.click(
      within(row).getByRole("button", { name: "Cancel the run of Apps" }),
    );
    fireEvent.click(
      within(
        await screen.findByRole("dialog", { name: "Cancel this run?" }),
      ).getByRole("button", { name: "Cancel run" }),
    );
    await screen.findByText("Cancelled the run of Apps");
    expect(
      availability(
        within(document.getElementById("run-run-6")!).getByRole("button", {
          name: "Cancel the run of Apps",
        }),
      ),
    ).toBe("Cancelling…");
    runs.release();
    await waitFor(() =>
      expect(
        within(document.getElementById("run-run-6")!).getByText("Cancelled"),
      ).toBeVisible(),
    );
  });

  it("shows a finished run's pull requests at once", async () => {
    const { api, queryClient } = await renderReseal({
      runs: [
        resealRun({ id: "run-6", status: "running", finished_at: undefined }),
      ],
      pullRequests: [],
    });
    const prs = section("Reseal pull requests");
    await within(prs).findByText("No open reseal pull requests");
    expect(
      within(section("Runs")).getByText("Refreshes every 10 seconds"),
    ).toBeVisible();
    // the run finishes and opens a pull request
    api.reseal.runs[0]!.status = "succeeded";
    api.reseal.pullRequests.push(
      resealPullRequest({ number: 12, run_id: "run-6" }),
    );
    await act(() =>
      queryClient.refetchQueries({ queryKey: ["reseal", "runs"] }),
    );
    expect(await within(prs).findByRole("link", { name: /#12/ })).toBeVisible();
    // nothing runs now, so the lists refresh less often
    expect(
      within(section("Runs")).getByText("Refreshes every minute"),
    ).toBeVisible();
  });
});

import { describe, it, expect, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import type { RepositoryFile } from "@/api/types";
import { KeyList } from "./KeyList";
import { NO_PENDING, keyStatuses, type PendingDocs } from "./keys";

/**
 * A file whose one document holds n keys and, unless told otherwise,
 * expects two it lacks.
 */
function file(n: number, expected = ["tax-api-key", "risk-token", "key-00"]) {
  return {
    path: "deploy/payments/sealed-secret.yaml",
    blob: "b",
    documents: [
      {
        index: 0,
        name: "payments",
        namespace: "apps",
        scope: "strict",
        keys: Array.from(
          { length: n },
          (_, i) => `key-${String(i).padStart(2, "0")}`,
        ),
        expected_keys: expected,
      },
    ],
  } satisfies RepositoryFile;
}

function renderList(
  f: RepositoryFile,
  pending: PendingDocs = NO_PENDING,
  sealing = true,
) {
  const onPick = vi.fn();
  const keys = keyStatuses(f, pending);
  render(
    <KeyList keys={keys} docs={1} onPick={sealing ? onPick : undefined} />,
  );
  return { onPick, keys };
}

function rows() {
  return within(screen.getByRole("list", { name: "Keys" }))
    .getAllByRole("listitem")
    .map((li) => li.dataset.key);
}

function views() {
  return within(screen.getByRole("group", { name: "Show keys" }));
}

describe("KeyList", () => {
  it.each([
    ["no keys", file(0, []), ["To Seal 0", "Pending 0", "All 0"]],
    ["two keys", file(2, []), ["To Seal 0", "Pending 0", "All 2"]],
    ["sixty keys", file(60), ["To Seal 2", "Pending 0", "All 62"]],
  ])("looks the same with %s", (_, f, labels) => {
    renderList(f);
    // a second filter on the page: `/` stays with the files
    const filter = screen.getByRole("searchbox", { name: "Filter keys" });
    expect(filter).not.toHaveAttribute("aria-keyshortcuts");
    expect(
      views()
        .getAllByRole("button")
        .map((b) => b.textContent),
    ).toEqual(labels);
    expect(views().getByRole("button", { name: labels[0] })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    // one joined group as tall as the filter, the chosen segment's edge on
    // the group's outline
    expect(screen.getByRole("group", { name: "Show keys" })).toHaveClass("h-8");
    expect(filter).toHaveClass("h-8");
    expect(views().getByRole("button", { name: labels[0] })).toHaveClass(
      "z-10",
      "border-primary",
      "bg-selected",
    );
    fireEvent.click(views().getByRole("button", { name: labels[2] }));
    expect(views().getByRole("button", { name: labels[2] })).toHaveClass(
      "z-10",
      "border-primary",
    );
    expect(views().getByRole("button", { name: labels[0] })).not.toHaveClass(
      "border-primary",
    );
  });

  it("opens on the keys to seal, not every key", () => {
    renderList(file(60));
    expect(rows()).toEqual(["tax-api-key", "risk-token"]);
    expect(screen.getByText("2 to seal")).toHaveClass("text-warning");
    fireEvent.click(views().getByRole("button", { name: "All 62" }));
    expect(rows()).toHaveLength(62);
  });

  it("says when every key is set, and offers them all", () => {
    renderList(file(20, []));
    expect(
      screen.queryByRole("list", { name: "Keys" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText("All 20 keys are set. Seal a new one below."),
    ).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Show All 20 Keys" }));
    expect(rows()).toHaveLength(20);
    expect(views().getByRole("button", { name: "All 20" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
  });

  it("offers to seal the first key of a file with none", () => {
    const { onPick } = renderList(file(0, []));
    expect(
      screen.getByText("No keys yet. Seal the first one below."),
    ).toBeVisible();
    const filter = screen.getByRole("searchbox", { name: "Filter keys" });
    fireEvent.change(filter, { target: { value: "api-token" } });
    fireEvent.click(
      screen.getByRole("button", { name: "Seal api-token as a New Key" }),
    );
    expect(onPick).toHaveBeenLastCalledWith("api-token");
  });

  it("searches every key, and picks the first match", () => {
    const { onPick } = renderList(file(60));
    const filter = screen.getByRole("searchbox", { name: "Filter keys" });

    // a search looks for a key the file holds, wherever it stands
    fireEvent.change(filter, { target: { value: "KEY-5" } });
    expect(views().getByRole("button", { name: "All 62" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    const matches = [
      "key-50",
      "key-51",
      "key-52",
      "key-53",
      "key-54",
      "key-55",
      "key-56",
      "key-57",
      "key-58",
      "key-59",
    ];
    expect(rows()).toEqual(matches);

    // narrowed to the keys to seal, it finds none, and offers the others
    fireEvent.click(views().getByRole("button", { name: "To Seal 2" }));
    expect(screen.getByText("No key to seal matches “KEY-5”.")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Show 10 Matches" }));
    expect(rows()).toEqual(matches);
    expect(screen.getByRole("status")).toHaveTextContent("10 of 62");
    fireEvent.keyDown(filter, { key: "Enter" });
    expect(onPick).toHaveBeenLastCalledWith("key-50");

    // a key the file lacks can be sealed as a new one, from the button or
    // with Enter
    fireEvent.change(filter, { target: { value: "webhook-secret" } });
    expect(screen.getByText("No key matches “webhook-secret”.")).toBeVisible();
    fireEvent.click(
      screen.getByRole("button", { name: "Seal webhook-secret as a New Key" }),
    );
    expect(onPick).toHaveBeenLastCalledWith("webhook-secret");
    fireEvent.keyDown(filter, { key: "Enter" });
    expect(onPick).toHaveBeenLastCalledWith("webhook-secret");

    // a name that cannot be a key is not offered
    fireEvent.change(filter, { target: { value: "bad/key" } });
    expect(
      screen.queryByRole("button", { name: /as a New Key/ }),
    ).not.toBeInTheDocument();
    fireEvent.click(
      within(screen.getByText(/No key matches/).parentElement!).getByRole(
        "button",
        { name: "Clear Filter" },
      ),
    );
    expect(filter).toHaveValue("");
    expect(filter).toHaveFocus();
    expect(rows()).toHaveLength(62);
  });

  it("shows the keys pending", () => {
    renderList(file(12), new Map([["key-03", new Set(["#0"])]]) as PendingDocs);
    fireEvent.click(views().getByRole("button", { name: "Pending 1" }));
    expect(rows()).toEqual(["key-03"]);
  });

  it("opens on every key for someone who can't seal", () => {
    renderList(file(4), NO_PENDING, false);
    expect(views().getByRole("button", { name: "All 6" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    expect(rows()).toHaveLength(6);
  });
});

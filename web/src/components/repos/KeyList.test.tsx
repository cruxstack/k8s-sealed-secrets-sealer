import { describe, it, expect, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import type { RepositoryFile } from "@/api/types";
import { KeyList, LONG_KEY_LIST } from "./KeyList";
import { NO_PENDING, keyStatuses, type PendingDocs } from "./keys";

/** A file whose one document holds n keys, and expects two it lacks. */
function file(n: number): RepositoryFile {
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
        expected_keys: ["tax-api-key", "risk-token", "key-00"],
      },
    ],
  };
}

function renderList(n: number, pending: PendingDocs = NO_PENDING) {
  const onPick = vi.fn();
  const keys = keyStatuses(file(n), pending);
  render(<KeyList keys={keys} docs={1} onPick={onPick} />);
  return { onPick, keys };
}

function rows() {
  return within(screen.getByRole("list", { name: "Keys" }))
    .getAllByRole("listitem")
    .map((li) => li.dataset.key);
}

describe("KeyList", () => {
  it("lists a short file's keys as they are", () => {
    renderList(4);
    expect(
      screen.queryByRole("searchbox", { name: "Filter keys" }),
    ).not.toBeInTheDocument();
    expect(rows()).toHaveLength(6);
  });

  it("gives a long list a filter that picks the first match or a new key", () => {
    const { onPick } = renderList(60);
    expect(rows()).toHaveLength(62);
    // a second filter on the page: `/` stays with the files
    const filter = screen.getByRole("searchbox", { name: "Filter keys" });
    expect(filter).not.toHaveAttribute("aria-keyshortcuts");

    fireEvent.change(filter, { target: { value: "KEY-5" } });
    expect(rows()).toEqual([
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
    ]);
    expect(screen.getByRole("status")).toHaveTextContent("10 of 62");
    fireEvent.keyDown(filter, { key: "Enter" });
    expect(onPick).toHaveBeenLastCalledWith("key-50");

    // a key the file lacks can be sealed as a new one, from the button or
    // with Enter
    fireEvent.change(filter, { target: { value: "webhook-secret" } });
    expect(screen.getByText("No key matches “webhook-secret”.")).toBeVisible();
    fireEvent.click(
      screen.getByRole("button", { name: "Seal webhook-secret as a new key" }),
    );
    expect(onPick).toHaveBeenLastCalledWith("webhook-secret");
    fireEvent.keyDown(filter, { key: "Enter" });
    expect(onPick).toHaveBeenLastCalledWith("webhook-secret");

    // a name that cannot be a key is not offered
    fireEvent.change(filter, { target: { value: "bad/key" } });
    expect(
      screen.queryByRole("button", { name: /as a new key/ }),
    ).not.toBeInTheDocument();
    fireEvent.click(
      within(screen.getByText(/No key matches/).parentElement!).getByRole(
        "button",
        { name: "Clear filter" },
      ),
    );
    expect(filter).toHaveValue("");
    expect(filter).toHaveFocus();
    expect(rows()).toHaveLength(62);
  });

  it("shows the keys to seal or those pending in a long list", () => {
    renderList(
      LONG_KEY_LIST,
      new Map([["key-03", new Set(["#0"])]]) as PendingDocs,
    );
    const views = screen.getByRole("group", { name: "Show keys" });
    expect(
      within(views)
        .getAllByRole("button")
        .map((b) => b.textContent),
    ).toEqual(["All 14", "To seal 2", "Pending 1"]);
    expect(
      within(views).getByRole("button", { name: "All 14" }),
    ).toHaveAttribute("aria-pressed", "true");
    // one joined group as tall as the filter, the chosen segment's edge on
    // the group's outline
    expect(views).toHaveClass("h-8");
    expect(screen.getByRole("searchbox", { name: "Filter keys" })).toHaveClass(
      "h-8",
    );
    expect(within(views).getByRole("button", { name: "All 14" })).toHaveClass(
      "z-10",
      "border-primary",
      "bg-selected",
    );
    fireEvent.click(within(views).getByRole("button", { name: "To seal 2" }));
    expect(
      within(views).getByRole("button", { name: "To seal 2" }),
    ).toHaveClass("z-10", "border-primary");
    expect(
      within(views).getByRole("button", { name: "All 14" }),
    ).not.toHaveClass("border-primary");
    expect(rows()).toEqual(["tax-api-key", "risk-token"]);
    fireEvent.click(within(views).getByRole("button", { name: "Pending 1" }));
    expect(rows()).toEqual(["key-03"]);
    expect(screen.getByText("2 to seal")).toHaveClass("text-warning");
  });

  it("offers no views when nothing needs a value or waits", () => {
    const onPick = vi.fn();
    const keys = keyStatuses(
      {
        ...file(20),
        documents: [{ ...file(20).documents![0]!, expected_keys: [] }],
      },
      NO_PENDING,
    );
    render(<KeyList keys={keys} docs={1} onPick={onPick} />);
    expect(
      screen.getByRole("searchbox", { name: "Filter keys" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("group", { name: "Show keys" }),
    ).not.toBeInTheDocument();
  });
});

import { describe, it, expect } from "vitest";
import { useRef, useState } from "react";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { Lock } from "lucide-react";
import { Alert } from "./alert";
import { Badge } from "./badge";
import { FilterInput } from "./filter-input";
import { RegionTag } from "./region-tag";
import { RelativeTime } from "./relative-time";
import { Dash, Table } from "./table";

describe("Alert", () => {
  it("shows its icon, heading, text and actions in the variant's colors", () => {
    render(
      <Alert
        variant="warning"
        role="status"
        aria-label="Key limit"
        heading="blue holds 210 keys"
        action={<button type="button">Fix</button>}
      >
        Past the limit, the oldest keys are left out.
      </Alert>,
    );
    const alert = screen.getByRole("status", { name: "Key limit" });
    expect(alert).toHaveClass("bg-warning-subtle", "border-warning/40");
    expect(alert).toHaveTextContent(
      "blue holds 210 keysPast the limit, the oldest keys are left out.",
    );
    expect(within(alert).getByText("blue holds 210 keys")).toHaveClass(
      "font-medium",
    );
    expect(
      within(alert).getByRole("button", { name: "Fix" }),
    ).toBeInTheDocument();
    // the icon is decoration in the variant's color
    const icon = alert.querySelector("svg");
    expect(icon).toHaveAttribute("aria-hidden", "true");
    expect(icon).toHaveClass("text-warning");
  });

  it("has a subtle background per variant, and takes another icon or none", () => {
    const { rerender } = render(
      <Alert variant="info" icon={Lock} role="alert">
        Read only
      </Alert>,
    );
    expect(screen.getByRole("alert")).toHaveClass("bg-info-subtle");
    expect(screen.getByRole("alert").querySelector("svg")).toHaveClass(
      "lucide-lock",
    );
    for (const variant of ["success", "destructive"] as const) {
      rerender(
        <Alert variant={variant} role="alert">
          Text
        </Alert>,
      );
      expect(screen.getByRole("alert")).toHaveClass(`bg-${variant}-subtle`);
    }
    rerender(
      <Alert variant="destructive" icon={null} role="alert">
        Text
      </Alert>,
    );
    expect(screen.getByRole("alert").querySelector("svg")).toBeNull();
  });
});

describe("Badge", () => {
  it("is neutral by default, and pending is info", () => {
    render(
      <>
        <Badge>3</Badge>
        <Badge variant="info">1 pending</Badge>
      </>,
    );
    expect(screen.getByText("3")).toHaveClass("bg-secondary");
    expect(screen.getByText("1 pending")).toHaveClass(
      "bg-info-subtle",
      "text-info",
    );
  });
});

function Filter() {
  const ref = useRef<HTMLInputElement>(null);
  const [value, setValue] = useState("");
  return (
    <FilterInput
      inputRef={ref}
      value={value}
      onValueChange={setValue}
      aria-label="Filter files"
    />
  );
}

describe("FilterInput", () => {
  it("shows its shortcut while empty and a clear button once it has text", () => {
    render(<Filter />);
    const input = screen.getByRole("searchbox", { name: "Filter files" });
    expect(input).toHaveAttribute("aria-keyshortcuts", "/");
    expect(screen.getByText("/")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Clear filter" }),
    ).not.toBeInTheDocument();

    fireEvent.change(input, { target: { value: "billing" } });
    // the hint and the clear button never sit on top of each other
    expect(screen.queryByText("/")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Clear filter" }));
    expect(input).toHaveValue("");
    expect(input).toHaveFocus();
    expect(screen.getByText("/")).toBeInTheDocument();
  });
});

describe("RegionTag", () => {
  it("shows a region in monospace, and says when there is none", () => {
    render(
      <>
        <RegionTag region="use1" />
        <RegionTag region="" />
      </>,
    );
    expect(screen.getByText("use1")).toHaveClass("font-mono", "text-xs");
    expect(screen.getByText("no region")).toHaveClass("font-sans");
  });
});

describe("RelativeTime", () => {
  it("reads relative, with the absolute time in its title", () => {
    const now = new Date("2026-11-10T12:00:00Z");
    render(
      <RelativeTime
        iso="2026-11-10T11:57:00Z"
        now={now}
        describe={(at) => `Last check-in ${at}`}
      />,
    );
    const time = screen.getByText("3m ago");
    expect(time.tagName).toBe("TIME");
    expect(time).toHaveAttribute("dateTime", "2026-11-10T11:57:00Z");
    expect(time).toHaveAttribute(
      "title",
      expect.stringMatching(/^Last check-in .*2026/),
    );
  });
});

describe("Table", () => {
  it("keeps visually hidden text inside its scroll box", () => {
    render(
      <Table>
        <caption className="sr-only">Keys</caption>
        <tbody>
          <tr>
            <td>
              <Dash />
            </td>
          </tr>
        </tbody>
      </Table>,
    );
    const box = screen.getByRole("table", { name: "Keys" }).parentElement;
    expect(box).toHaveClass("relative", "overflow-x-auto", "shadow-xs");
    // an empty cell is an em dash in the sans font, even in a mono column
    expect(screen.getByLabelText("none")).toHaveClass("font-sans");
  });
});

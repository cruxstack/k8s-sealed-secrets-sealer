import { describe, it, expect } from "vitest";
import { useRef, useState } from "react";
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { Lock } from "lucide-react";
import { Alert } from "./alert";
import { Badge } from "./badge";
import { FieldLabel } from "./field-label";
import { IconButton } from "./icon-button";
import { ReasonButton } from "./reason-button";
import { FilterInput } from "./filter-input";
import { InfoTip } from "./info-tip";
import { RegionTag } from "./region-tag";
import { RelativeTime } from "./relative-time";
import { Dash, Table } from "./table";
import { TooltipProvider } from "./tooltip";

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

describe("FieldLabel", () => {
  const help = "The name in spec.encryptedData.";

  it("names the field, with its help as the field's description", () => {
    render(
      <TooltipProvider>
        <FieldLabel htmlFor="key" helpId="key-help" help={help}>
          Key
        </FieldLabel>
        <input id="key" aria-describedby="key-help" />
      </TooltipProvider>,
    );
    const input = screen.getByRole("textbox", { name: "Key" });
    expect(input).toHaveAccessibleDescription(help);
    // the help is out of sight until asked for
    expect(screen.getByText(help)).not.toBeVisible();
    const about = screen.getByRole("button", { name: "About Key" });
    expect(about).toHaveAttribute("type", "button");
    expect(about).toHaveAccessibleDescription(help);
  });

  it("shows the help on focus and on a tap", async () => {
    render(
      <TooltipProvider>
        <FieldLabel id="regions" helpId="regions-help" help={help}>
          Regions
        </FieldLabel>
        <div role="group" aria-labelledby="regions" />
      </TooltipProvider>,
    );
    // without htmlFor, it names a group
    expect(screen.getByRole("group", { name: "Regions" })).toBeInTheDocument();
    const about = screen.getByRole("button", { name: "About Regions" });
    fireEvent.focus(about);
    await waitFor(() => expect(tooltipShown()).toBe(help));
    fireEvent.keyDown(about, { key: "Escape" });
    await waitFor(() => expect(tooltipShown()).toBeUndefined());
    // a touch screen has no hover: a tap shows it
    fireEvent.pointerDown(about, { pointerType: "touch" });
    fireEvent.click(about);
    await waitFor(() => expect(tooltipShown()).toBe(help));
  });
});

describe("InfoTip", () => {
  it("has its text as its description, and shows it on focus", async () => {
    render(
      <TooltipProvider>
        <p>
          Sealed.{" "}
          <InfoTip label="About This Seal">One agent sealed it.</InfoTip>
        </p>
      </TooltipProvider>,
    );
    const about = screen.getByRole("button", { name: "About This Seal" });
    expect(about).toHaveAttribute("type", "button");
    expect(about).toHaveAccessibleDescription("One agent sealed it.");
    // out of sight until asked for, and not read as part of the sentence
    expect(screen.getByText("One agent sealed it.")).not.toBeVisible();
    fireEvent.focus(about);
    await waitFor(() => expect(tooltipShown()).toBe("One agent sealed it."));
  });
});

describe("FilterInput", () => {
  it("shows its shortcut while empty and a clear button once it has text", () => {
    render(<Filter />);
    const input = screen.getByRole("searchbox", { name: "Filter files" });
    expect(input).toHaveAttribute("aria-keyshortcuts", "/");
    expect(screen.getByText("/")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Clear Filter" }),
    ).not.toBeInTheDocument();

    fireEvent.change(input, { target: { value: "billing" } });
    // the hint and the clear button never sit on top of each other
    expect(screen.queryByText("/")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Clear Filter" }));
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

  it("says what an empty cell stands for when it is not none", () => {
    render(<Dash label="not counted" />);
    expect(screen.getByLabelText("not counted")).toHaveTextContent("—");
  });
});

/** The text of the tooltip on screen, if one is. */
function tooltipShown() {
  return document.querySelector("[data-radix-popper-content-wrapper]")
    ?.textContent;
}

describe("IconButton", () => {
  const why = "Every cluster must count references first.";

  it("names what it does in a tooltip on focus, and acts on a click", async () => {
    let clicked = 0;
    render(
      <TooltipProvider>
        <IconButton
          label="Delete"
          aria-label="Delete key abc"
          onClick={() => clicked++}
        >
          <Lock aria-hidden="true" />
        </IconButton>
      </TooltipProvider>,
    );
    const button = screen.getByRole("button", { name: "Delete key abc" });
    expect(button).not.toHaveAttribute("aria-disabled");
    // the conventions' icon size: a 36px target
    expect(button).toHaveClass("h-9", "w-9");
    fireEvent.focus(button);
    expect(await screen.findByRole("tooltip")).toHaveTextContent(/^Delete$/);
    fireEvent.click(button);
    expect(clicked).toBe(1);
  });

  it("when it cannot be used, stays focusable with its reason as its description", () => {
    render(
      <TooltipProvider>
        <IconButton label="Delete" reason={why} aria-label="Delete key abc">
          <Lock aria-hidden="true" />
        </IconButton>
      </TooltipProvider>,
    );
    const button = screen.getByRole("button", { name: "Delete key abc" });
    expect(button).toHaveAttribute("aria-disabled", "true");
    expect(button).not.toBeDisabled();
    expect(button).toHaveClass("opacity-50", "cursor-not-allowed");
    // always described, not only while the tooltip shows
    expect(button).toHaveAccessibleDescription(why);
    button.focus();
    expect(button).toHaveFocus();
  });

  it("shows why on focus and on a tap, and does nothing else", async () => {
    let clicked = 0;
    render(
      <TooltipProvider>
        <IconButton
          label="Delete"
          reason={why}
          aria-label="Delete key abc"
          onClick={() => clicked++}
        >
          <Lock aria-hidden="true" />
        </IconButton>
      </TooltipProvider>,
    );
    const button = screen.getByRole("button", { name: "Delete key abc" });
    fireEvent.focus(button);
    expect(await screen.findByRole("tooltip")).toHaveTextContent(/^Delete$/);
    expect(tooltipShown()).toContain(why);
    // read once: the reason, then what the button does
    expect(button).toHaveAccessibleDescription(`${why} Delete`);
    fireEvent.keyDown(document.activeElement ?? document.body, {
      key: "Escape",
    });
    await waitFor(() =>
      expect(screen.queryByRole("tooltip")).not.toBeInTheDocument(),
    );
    // a touch screen has no hover: a tap shows it
    fireEvent.pointerDown(button, { pointerType: "touch" });
    fireEvent.click(button);
    await waitFor(() => expect(tooltipShown()).toContain(why));
    expect(clicked).toBe(0);
  });
});

describe("ReasonButton", () => {
  const why = "An env has at most 50 schedules. Delete one first.";

  it("acts on a click, with no tooltip, when it can be used", () => {
    let clicked = 0;
    render(
      <TooltipProvider>
        <ReasonButton onClick={() => clicked++}>New Schedule</ReasonButton>
      </TooltipProvider>,
    );
    const button = screen.getByRole("button", { name: "New Schedule" });
    expect(button).not.toHaveAttribute("aria-disabled");
    fireEvent.click(button);
    expect(clicked).toBe(1);
  });

  it("when it cannot be used, keeps its label, says why, and does nothing else", async () => {
    let clicked = 0;
    render(
      <TooltipProvider>
        <ReasonButton reason={why} onClick={() => clicked++}>
          New Schedule
        </ReasonButton>
      </TooltipProvider>,
    );
    const button = screen.getByRole("button", { name: "New Schedule" });
    expect(button).toHaveAttribute("aria-disabled", "true");
    expect(button).not.toBeDisabled();
    expect(button).toHaveClass("opacity-50", "cursor-not-allowed");
    expect(button).toHaveAccessibleDescription(why);
    fireEvent.focus(button);
    expect(await screen.findByRole("tooltip")).toHaveTextContent(why);
    fireEvent.keyDown(document.activeElement ?? document.body, {
      key: "Escape",
    });
    await waitFor(() =>
      expect(screen.queryByRole("tooltip")).not.toBeInTheDocument(),
    );
    // a tap shows why
    fireEvent.pointerDown(button, { pointerType: "touch" });
    fireEvent.click(button);
    await waitFor(() => expect(tooltipShown()).toContain(why));
    expect(clicked).toBe(0);
  });
});

import { describe, it, expect, afterEach } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { ThemeProvider, useTheme } from "./theme-provider";

function Toggle() {
  const { resolvedTheme, setTheme } = useTheme();
  return (
    <button
      type="button"
      onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
    >
      {resolvedTheme}
    </button>
  );
}

describe("ThemeProvider", () => {
  const root = document.documentElement;
  afterEach(() => {
    root.className = "";
    localStorage.clear();
  });

  it("always sets .light or .dark, so the first-paint CSS stops applying", () => {
    render(
      <ThemeProvider defaultTheme="system" storageKey="test-theme-1">
        <Toggle />
      </ThemeProvider>,
    );
    // the test environment prefers light
    expect(root).toHaveClass("light");
    expect(root).not.toHaveClass("dark");
  });

  it("switches with transitions off for the swap, and remembers the choice", async () => {
    render(
      <ThemeProvider defaultTheme="light" storageKey="test-theme-2">
        <Toggle />
      </ThemeProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: "light" }));
    expect(root).toHaveClass("dark", "theme-switching");
    expect(root).not.toHaveClass("light");
    expect(localStorage.getItem("test-theme-2")).toBe("dark");
    // transitions come back on the next frame
    await act(() => new Promise((r) => requestAnimationFrame(r)));
    expect(root).not.toHaveClass("theme-switching");
    expect(screen.getByRole("button", { name: "dark" })).toBeInTheDocument();
  });
});

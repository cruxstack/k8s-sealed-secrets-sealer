import { describe, it, expect } from "vitest";
import css from "./index.css?raw";

/** The custom properties declared in every `selector {` block. */
function tokens(selector: string): Record<string, string> {
  const out: Record<string, string> = {};
  let start = css.indexOf(`${selector} {`);
  expect(start, `${selector} block`).toBeGreaterThanOrEqual(0);
  while (start >= 0) {
    const body = css.slice(start, css.indexOf("}", start));
    for (const m of body.matchAll(/--([\w-]+):\s*([^;]+);/g)) {
      out[m[1]!] = m[2]!.trim();
    }
    start = css.indexOf(`${selector} {`, start + 1);
  }
  return out;
}

describe("index.css", () => {
  it("paints people who prefer dark with the dark theme's exact tokens", () => {
    const dark = tokens(".dark");
    expect(Object.keys(dark).length).toBeGreaterThan(20);
    expect(tokens(":root:not(.light)")).toEqual(dark);
  });

  it("defines every token in both themes", () => {
    const light = tokens(":root");
    const dark = tokens(".dark");
    // the radius is the same in both
    delete light.radius;
    expect(Object.keys(dark).sort()).toEqual(Object.keys(light).sort());
    for (const name of [
      "info",
      "info-subtle",
      "success-subtle",
      "warning-subtle",
      "destructive-subtle",
      "selected",
    ]) {
      expect(light[name], name).toBeDefined();
    }
  });
});

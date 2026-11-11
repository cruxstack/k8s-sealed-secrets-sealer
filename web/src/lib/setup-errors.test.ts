import { describe, it, expect } from "vitest";
import { GENERIC_SETUP_ERROR, setupErrorMessage } from "./setup-errors";

describe("setupErrorMessage", () => {
  it("returns null when there is no error code", () => {
    expect(setupErrorMessage(null)).toBeNull();
    expect(setupErrorMessage(undefined)).toBeNull();
    expect(setupErrorMessage("")).toBeNull();
  });

  it("maps every code the setup's callback sends", () => {
    expect(setupErrorMessage("state")).toMatch(/couldn't be verified/);
    expect(setupErrorMessage("github")).toMatch(/didn't hand over/);
    expect(setupErrorMessage("wrong_owner")).toMatch(
      /outside the organization/,
    );
    expect(setupErrorMessage("already_set_up")).toMatch(/set up first/);
    expect(setupErrorMessage("store")).toMatch(/couldn't be saved/);
    expect(setupErrorMessage("busy")).toMatch(/Wait a minute/);
  });

  it("never shows an unknown code, or an inherited key", () => {
    expect(setupErrorMessage("<script>")).toBe(GENERIC_SETUP_ERROR);
    expect(setupErrorMessage("__proto__")).toBe(GENERIC_SETUP_ERROR);
    expect(setupErrorMessage("toString")).toBe(GENERIC_SETUP_ERROR);
  });
});

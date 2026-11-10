import { describe, it, expect } from "vitest";
import { GENERIC_LOGIN_ERROR, loginErrorMessage } from "./login-errors";

describe("loginErrorMessage", () => {
  it("returns null when there is no error code", () => {
    expect(loginErrorMessage(null)).toBeNull();
    expect(loginErrorMessage(undefined)).toBeNull();
    expect(loginErrorMessage("")).toBeNull();
  });

  it("maps every code the callback sends", () => {
    expect(loginErrorMessage("access_denied")).toMatch(/cancelled or denied/);
    expect(loginErrorMessage("not_member")).toMatch(
      /member of the GitHub organization/,
    );
    expect(loginErrorMessage("not_in_team")).toMatch(/GitHub team allowed/);
    expect(loginErrorMessage("state_mismatch")).toMatch(/state mismatch/);
    expect(loginErrorMessage("github_error")).toMatch(
      /GitHub returned an error/,
    );
  });

  it("ignores inherited Object.prototype keys", () => {
    for (const code of [
      "__proto__",
      "constructor",
      "toString",
      "hasOwnProperty",
      "valueOf",
    ]) {
      expect(loginErrorMessage(code)).toBe(GENERIC_LOGIN_ERROR);
    }
  });

  it("never echoes arbitrary input", () => {
    expect(loginErrorMessage("Your account is locked, call +1-555-0100")).toBe(
      GENERIC_LOGIN_ERROR,
    );
    expect(loginErrorMessage("<img src=x onerror=alert(1)>")).toBe(
      GENERIC_LOGIN_ERROR,
    );
  });
});

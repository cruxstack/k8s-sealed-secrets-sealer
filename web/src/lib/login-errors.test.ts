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
    expect(loginErrorMessage("not_in_team")).toMatch(
      /in a team that may use Sealer/,
    );
    expect(loginErrorMessage("state_mismatch")).toMatch(/couldn't be verified/);
    expect(loginErrorMessage("github_error")).toMatch(
      /GitHub returned an error/,
    );
  });

  it("says what to do next for every code", () => {
    for (const code of [
      "access_denied",
      "not_member",
      "not_in_team",
      "state_mismatch",
      "github_error",
      "something_else",
    ]) {
      expect(loginErrorMessage(code)).toMatch(/sign in again/i);
    }
    // a refusal says who can let the user in
    expect(loginErrorMessage("not_member")).toMatch(
      /ask an organization owner/i,
    );
    expect(loginErrorMessage("not_in_team")).toMatch(/ask an admin/i);
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

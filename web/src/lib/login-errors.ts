/** Messages for the `?error=` codes the OAuth callback redirects with. */
const LOGIN_ERROR_MESSAGES: Readonly<Record<string, string>> = {
  access_denied: "GitHub sign-in was cancelled or denied. Please try again.",
  not_member:
    "Access denied. You must be a member of the GitHub organization to use this app.",
  not_in_team:
    "Access denied. You must be a member of a GitHub team allowed to use this environment.",
  state_mismatch:
    "Sign-in could not be verified (state mismatch). Please try again.",
  github_error: "GitHub returned an error. Please try again.",
};

export const GENERIC_LOGIN_ERROR = "Sign-in failed. Please try again.";

/**
 * Map a login `?error=` code to a user-facing message. Unknown codes get a
 * generic message: the query string is attacker-controlled, so it is never
 * displayed verbatim, and inherited keys such as `__proto__` are ignored.
 */
export function loginErrorMessage(
  code: string | null | undefined,
): string | null {
  if (!code) return null;
  if (Object.hasOwn(LOGIN_ERROR_MESSAGES, code)) {
    return LOGIN_ERROR_MESSAGES[code] ?? GENERIC_LOGIN_ERROR;
  }
  return GENERIC_LOGIN_ERROR;
}

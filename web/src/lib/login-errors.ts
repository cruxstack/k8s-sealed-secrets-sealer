/**
 * Messages for the `?error=` codes the OAuth callback redirects with. Each
 * says what happened, then what to do next.
 */
const LOGIN_ERROR_MESSAGES: Readonly<Record<string, string>> = {
  access_denied:
    "GitHub sign-in was cancelled or denied. Sign in again when you're ready.",
  not_member:
    "Your GitHub account isn't a member of the GitHub organization that runs Sealer. Ask an organization owner to add you, then sign in again.",
  not_in_team:
    "Your GitHub account isn't in a team that may use Sealer. Ask an admin to add you, then sign in again.",
  state_mismatch:
    "Sign-in couldn't be verified, so it was stopped. Sign in again from this page.",
  github_error:
    "GitHub returned an error during sign-in. Wait a moment, then sign in again.",
};

export const GENERIC_LOGIN_ERROR =
  "Sign-in failed. Sign in again, and ask an admin if it keeps failing.";

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

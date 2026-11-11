/**
 * Messages for the `?error=` codes the GitHub App setup's callback sends
 * back with. Each says what happened, then what to do next.
 */
const SETUP_ERROR_MESSAGES: Readonly<Record<string, string>> = {
  state:
    "The setup couldn't be verified, so nothing was saved. Start again from this page, in the same browser.",
  github:
    "GitHub didn't hand over the new App's credentials, so nothing was saved. Delete the App from your organization's settings on GitHub if it was created, then start again.",
  wrong_owner:
    "The App was created outside the organization Sealer is set up for, so it wasn't used. Delete it on GitHub, then start again and create it in the organization.",
  already_set_up:
    "Another GitHub App was set up first, and is the one Sealer uses. Delete the App you just created on GitHub.",
  store:
    "The App was created, but its credentials couldn't be saved. Ask whoever runs Sealer to check its access to the SSM parameter, delete the App on GitHub, then start again.",
  busy: "Too many setups were tried this minute. Wait a minute, then start again.",
};

export const GENERIC_SETUP_ERROR =
  "The setup didn't finish. Start again, and ask whoever runs Sealer if it keeps failing.";

/**
 * Map a setup `?error=` code to a message. Unknown codes get a generic
 * message: the query string is not trusted, so it is never shown verbatim.
 */
export function setupErrorMessage(
  code: string | null | undefined,
): string | null {
  if (!code) return null;
  if (Object.hasOwn(SETUP_ERROR_MESSAGES, code)) {
    return SETUP_ERROR_MESSAGES[code] ?? GENERIC_SETUP_ERROR;
  }
  return GENERIC_SETUP_ERROR;
}

# UI Conventions

Use these conventions when adding or changing pages in the web UI (`web/`).
They describe what the repository workspace and the fleet page already do, so
new screens look and behave the same.

## Pages

Every signed-in page sits in `AppShell`: the header with the env badge, the
navigation, the search button, the theme toggle and the account menu, then
the page content in a centered column. A page starts with what matters most
(the fleet page opens with the env key banner) and then its main table or
form. Sealing is what people come for, so the home page is Secrets
(`/secrets`): their repositories, each opening its workspace at
`/secrets/{owner}/{repo}`. The navigation holds what everyone uses.

The fleet (`/fleet`) is for admins. They reach it from the account menu, the
palette and the env badge; nobody else is offered it, and someone who opens
the URL anyway is told it is for admins. Everyone sees whether sealing works
from the dot on the env badge, with a summary in its tooltip.

## Workspaces

A screen where people pick one thing and work on it is a workspace: the
things to pick on the left, in a filterable list, and the picked one on the
right, with its form. The repository page is one: files on the left, the
file's documents and seal form on the right, and the pending changes under
them. The pick is in the URL (`?file=`), so a reload or a shared link opens
the same thing, and the first usable item is picked when none is.

Show hints where the decision is made. A file's description sits under its
path in the list and above its documents, its docs are a link in its header,
and expected keys it lacks are dashed amber, in the list as a count, in the
documents by name and in the form as chips that fill the key. Hints warn and
never block: a key the file does not expect gets an amber note, and the
value can still be sealed.

## Keyboard

People who use this every day use it from the keyboard:

- ⌘K (Ctrl+K) opens the command palette anywhere: repositories, pages and
  actions. Add new destinations there.
- `/` focuses the page's filter. Enter in a filter opens the first match,
  and the arrow keys move through the list.
- In a form, Enter moves to the next field and ⌘/Ctrl+Enter submits. After a
  submit succeeds, the form clears and the first field takes focus for the
  next one; after a failure, what was typed stays.
- Picking an item focuses its form, but nothing steals focus on page load.
- Show a shortcut where it applies with `Kbd`, and set `aria-keyshortcuts`
  on the control it triggers.

Pages that show live state refresh on their own with TanStack Query
(`refetchInterval`) and say how often in small muted text beside the section
title ("Refreshes every 15 seconds"). Never make people reload to see an agent
come back.

## Tables

- Use semantic table markup: a `caption` (visually hidden when the section
  title already names the table), `th scope="col"` headers, and the row's
  identifier as `th scope="row"`.
- Headers are short, one or two words, in `text-xs` uppercase muted text.
- Identifiers (agent IDs, fingerprints, namespaces) are monospace and never
  wrap (`whitespace-nowrap`); the table scrolls sideways inside its own
  rounded, bordered box (`overflow-x-auto`) instead.
- Status is a `Badge`: green for healthy, amber for needs attention (out of
  sync, missing keys, stale check-in), red for failed or never checked in.
  Pair the color with a word; color alone carries no meaning.
- Counts are right-aligned and tabular. A count that needs attention (missing
  keys) uses the amber text color.
- Times are relative ("4s ago") with the absolute time in the `title` and a
  `time dateTime` element.
- Long values (key fingerprints) are shortened with an ellipsis, with the
  full value in the `title` and a copy button where people need to paste it.
- An empty cell shows an em dash, not a blank.

## Toolbars

A section heading row holds the section title on the left and its controls on
the right (filters, refresh status, export). Keep a toolbar to one row on a
desktop width; if a section needs more than three controls, it needs a
different design.

## Row details

Rows are dense summaries. Detail that does not fit a cell (an agent's full key
list, its issues) goes in the row's issues column as short sentences, or in a
detail view reached from the row. A row that opens something shows it on
hover and has a visible affordance; a row that opens nothing does not look
pressable.

## Buttons

- One primary button per card or dialog, for its main action (Sign in with
  GitHub, Seal, Open pull request). Everything else is `outline` or `ghost`.
- A button that just succeeded may show it for a moment ("Sealed", in the
  success color) before returning to its label.
- Icon-only buttons (theme toggle, copy) have an `aria-label` and a tooltip
  or `title`.
- Destructive or irreversible actions use the `destructive` variant and
  confirm in a dialog that names what will happen.
- Navigation that leaves the app (signing in with GitHub) is a link styled as
  a button, not a `fetch`.

## Messages

- Something that finished (a value sealed, a change removed) gets a toast
  (`toast` from sonner) that names what happened. A toast never carries a
  secret value, and never replaces an error that needs action.
- The end of a flow (a pull request opened) gets a dialog with the way
  forward ("View pull request") and the way back ("Keep sealing").
- Errors from the API show the server's short message in an alert, never a
  stack trace or a raw status code alone.
- Sign-in refusals map each `/login?error=` code to a sentence that says what
  to do next.
- Loading states use `Skeleton` shapes of the content they replace.
- Empty states say why the screen is empty and what to do about it.

## Theme and assets

Every screen works in the light and the dark theme; check both. The UI is
served with a strict Content Security Policy: scripts only from the app's own
bundle (never inline, never another origin) and no third-party origins except
GitHub avatars. Inline styles are allowed because Radix menus and dialogs
inject them. Bundle fonts and icons (lucide-react). After changing a screen,
open its menus and dialogs and check the browser console for CSP
violations.

## Accessibility

Keep keyboard focus visible, give every control an accessible name, use
`role="alert"` for errors that appear after an action, and keep text contrast
at WCAG AA in both themes.

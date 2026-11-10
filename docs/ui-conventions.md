# UI Conventions

Use these conventions when adding or changing pages in the web UI (`web/`).
They describe what the repository workspace and the fleet page already do, so
new screens look and behave the same.

## Pages

Every signed-in page sits in `AppShell`: the header with the env badge, the
navigation, the search button, the theme toggle and the account menu, then
the page content in a centered column. A page opens with its title (an `h1`)
and one line of context, then what matters most (the fleet's env key banner)
and its main table or form. A page under another one puts the way back in
its title as a breadcrumb ("Secrets / example-org/apps") rather than on a
line of its own. Sealing is what people come for, so the home page is Secrets
(`/secrets`): their repositories, each opening its workspace at
`/secrets/{owner}/{repo}`. The navigation holds what everyone uses.

Pages work down to a phone's width (390px) without scrolling sideways. Grids
collapse to one column with `grid-cols-1`, whose track lets items shrink
(a bare `grid` sizes its column to the widest item), and only a wide table
scrolls, inside its own box.

The fleet (`/fleet`) is for admins. They reach it from the account menu, the
palette and the env badge; nobody else is offered it, and someone who opens
the URL anyway is told it is for admins. Everyone sees whether sealing works
from the dot on the env badge, with a summary in its tooltip.

## Workspaces

A screen where people pick one thing and work on it is a workspace: the
things to pick on the left, in a filterable list, and the picked one on the
right, with its form. What the work adds up to (the pending changes, with
the button that opens the pull request) sits under the list, like a cart.
The left column stays in view as the page scrolls, and its list scrolls on
its own, so the cart is never far. The pick is in the URL (`?file=`), so a
reload or a shared link opens the same thing, and the first usable item is
picked when none is.

The repository page is one. The picked file shows, in order:

1. its path, description and docs link;
2. its keys, one row each, saying where the key stands across the file's
   documents: in all of them, in some (naming the others), expected but in
   none, or waiting in the pending changes;
3. the seal form;
4. the documents a value is sealed for, with their regions and scopes.

The keys come first because they are what people act on: picking a row fills
the form's key and moves to the value. The documents come last because they
rarely change and only need checking.

When a file's documents are in more than one region, each key row also shows
a chip per region with where the key stands there, and the form gets a
choice of regions, all chosen at first. Picking a region's chip fills the
key and limits the seal to that region. A limited seal says so everywhere it
shows: the form's heading and note name the regions, the documents left out
are dimmed, and the pending change carries its regions as badges. The
regions chosen stay for the next value, since values that differ by region
usually come several at a time.

Show hints where the decision is made. A file's description sits under its
path in the list and in its header, its docs are a link in its header, and
expected keys it lacks are dashed amber: in the list as a count and in the
key rows. Hints warn and never block: a key the file does not expect gets an
amber note, and the value can still be sealed.

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
  rounded, bordered box (`overflow-x-auto`) instead. A table of two or three
  columns in a workspace may wrap its identifiers instead
  (`[overflow-wrap:anywhere]`), so it fits a phone without scrolling.
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

- Something that finished away from where people are looking (a change
  removed, changes discarded) gets a toast (`toast` from sonner) that names
  what happened. A result shown where people acted (a seal's status line
  under the form, its change appearing in the cart) needs no toast as well.
  A toast never carries a secret value, and never replaces an error that
  needs action.
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

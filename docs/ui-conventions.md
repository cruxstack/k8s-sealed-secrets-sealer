# UI Conventions

Use these conventions when adding or changing pages in the web UI (`web/`).
They describe what the repository workspace and the fleet page already do, so
new screens look and behave the same.

## Pages

Every signed-in page sits in `AppShell`: the header with the env badge, the
navigation, the search button, the theme toggle and the account menu, then
the page content in a centered column. A page opens with its title (an `h1`
in `text-xl font-semibold`) and one line of context, then what matters most
(the fleet's env key banner) and its main table or form. A page under
another one puts the way back in its title as a breadcrumb ("Secrets /
example-org/apps") rather than on a line of its own. Sealing is what people
come for, so the home page is Secrets (`/{env}/secrets`): their
repositories, each opening its workspace at `/{env}/secrets/{owner}/{repo}`.
The navigation holds what everyone uses, and Fleet for the env's admins; the
current page's item is marked (`aria-current="page"`).

Every page but signing in is about one env, named first in its path, so a
link keeps its env. Components read the env from `useEnv()`, never from the
session, and API calls go to it on their own (`/api/v1/envs/{env}/...`). `/`
opens the first env the user may use, and paths from before envs were in
them (`/secrets/...`, `/fleet`) open the same page there. An env the user may
not use says so and links to those they may. Moving to another env starts
its pages afresh, so nothing loaded for one env shows in another.

A page that does not exist, a page for admins opened by someone else, and an
env the user may not use are each an `EmptyState` with `page` set: in the
app's shell, an icon, the title as the page's `h1`, a line saying why, and
the way forward as an outline `sm` button ("Go to Secrets", "Back to
Secrets", "Go to dev"). The router's `notFoundComponent` (on the root and
`$env` routes) renders `NotFound`.

Pages work down to a phone's width (390px) without scrolling sideways. Grids
collapse to one column with `grid-cols-1`, whose track lets items shrink
(a bare `grid` sizes its column to the widest item), and only a wide table
scrolls, inside its own box.

The fleet (`/{env}/fleet`) is for the env's admins. They reach it from the
navigation, the account menu, the palette and the env badge, always labelled
"Fleet"; nobody else is offered it, and someone who opens the URL anyway is
told it is for admins. Everyone sees whether sealing works from the dot on
the env badge, with a summary in its tooltip; when it doesn't, the workspace
says so above the files, since seals would fail.

Under its agents, the fleet lists the env's keys, newest first: how many
clusters hold each, its escrowed copies, and its status as a badge (env key,
active, revoked, future-dated). Revoking a key is a ghost button on its row
that opens a dialog saying what revoking does and does not do, with a
destructive confirm; a revoked key's row is muted and offers Reinstate,
which confirms in a dialog too, since the key goes back into every cluster
and may become the env key. A notice under the env key warns when a
cluster's keys reach half or 80% of the key limit, or go past it. With no
env key, the banner says why and what happens next: keys out of sync (and
whether any agent has checked in), or a new key needed when every key the
clusters share is revoked or not valid yet.

Someone who may use several envs gets a switcher in place of the badge: the
same dot and name, opening a menu of their envs (the current one checked,
those they administer marked), the env's sealing summary, and Fleet for
admins. The palette offers the other envs too.

## Workspaces

A screen where people pick one thing and work on it is a workspace: the
things to pick on the left, in a filterable list, and the picked one on the
right, with its form. What the work adds up to (the pending changes, with
the button that opens the pull request) sits under the list, like a cart.
The left column stays in view as the page scrolls, `lg:top-6` below the
header with a height to match, and its list scrolls on its own, so the
cart's footer is always reachable. The pick is in the URL (`?file=`), so a
reload or a shared link opens the same thing, and the first usable item is
picked when none is.

The repository page is one. The picked file shows, in order:

1. its path, description and docs link;
2. its keys, one row each, saying where the key stands across the file's
   documents: in all of them, in some (naming the others), expected but in
   none, or waiting in the pending changes;
3. the seal form;
4. its documents, with their regions and scopes.

The keys come first because they are what people act on: picking a row fills
the form's key and moves to the value. The documents come last because they
rarely change and only need checking. A file nothing can be sealed into says
why in a warning alert where the form would be.

When a file's documents are in more than one region, each key row also shows
a chip per region with where the key stands there, and the form gets a
choice of regions, all chosen at first. Picking a region's chip fills the
key and limits the seal to that region. A limited seal says so everywhere it
shows: the form's heading and note name the regions, the documents left out
say "not in this seal", and the pending change carries its regions as tags.
The regions chosen stay for the next value, since values that differ by
region usually come several at a time.

A pending change sealed with a key an admin has since revoked is amber "Seal
again" everywhere it shows: its badge in the cart, its key's row and region
chips, and its file in the list. "Seal again" means only that; a key whose
pending value is fine offers "Replace". The pull request button stays
disabled until the value is sealed again or removed, with the reason in
muted text under it (and in its `title`), as for any disabled action.

A seal's status line under the form ("Sealed api-token for 2 documents…")
lasts as long as its change: once the change is removed, discarded or sent
in a pull request, the line goes. With nothing pending, the cart says what
will gather there and shows no footer.

Show hints where the decision is made. A file's description sits under its
path in the list and in its header, its docs are a link in its header, and
expected keys it lacks are dashed amber: in the list as a count and in the
key rows. A file's badges in the list always sit on their own row, under its
summary. Hints warn and never block: a key the file does not expect gets an
amber note, and the value can still be sealed.

## Keyboard

People who use this every day use it from the keyboard:

- ⌘K (Ctrl+K) opens the command palette anywhere: repositories, pages and
  actions. Add new destinations there.
- `/` focuses the page's filter. Enter in a filter opens the first match,
  and the arrow keys move through the list. Use `FilterInput`: it shows the
  `/` hint while empty and its own clear button once it has text, with the
  browser's clear button hidden so the two never overlap.
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

## Headings

There are two section headings, and no uppercase ones:

- A section of a page, above its table or cards, uses `SectionHeading`: the
  title in `text-base font-semibold` with its count in muted `text-sm`
  beside it ("Agents 3 of 3 healthy"), and notes or controls on the right.
- A section inside a card uses `CardHeading`: `text-sm font-semibold` with
  its count as a secondary `Badge` ("Files 4", "Documents 2").

Only table column headers are uppercase (see Tables).

## Tables

- Use the table shell in `components/ui/table.tsx` (`Table`, `TableHeader`,
  `TableHead`, `TableRow`, `TableCell`): a rounded, bordered box with a light
  shadow and a tinted header band, `px-4 py-2.5` header cells and
  `px-4 py-3` body cells. The box is `relative` and scrolls sideways on its
  own (`overflow-x-auto`), so visually hidden text inside it never widens
  the page.
- Use semantic table markup: a `caption` (visually hidden when the section
  title already names the table), `th scope="col"` headers, and the row's
  identifier as `th scope="row"`.
- Headers are short, one or two words, in `text-xs` uppercase muted text.
- Identifiers (agent IDs, fingerprints, namespaces) are monospace and never
  wrap (`whitespace-nowrap`); the table scrolls inside its box instead. A
  table of two or three columns in a workspace may wrap its identifiers
  instead (`[overflow-wrap:anywhere]`), so it fits a phone without scrolling.
- Status is a `Badge`: green for healthy, amber for needs attention (out of
  sync, missing keys, stale check-in), red for failed or never checked in.
  Pair the color with a word; color alone carries no meaning.
- Counts are right-aligned and tabular. A count that needs attention (missing
  keys) uses the amber text color.
- Rows whose cells differ in height (a badge over a time) center their cells
  vertically, and a column of row actions has a fixed width, so nothing
  shifts when an action changes the row (Revoke becomes Reinstate).
- Long values (key fingerprints) are shortened with an ellipsis, with the
  full value in the `title` and a copy button where people need to paste it.
- An empty cell shows an em dash (`Dash`), in the sans font even in a
  monospace column.

## Names, regions and times

- Env names are sans, in `font-medium` where they stand out ("the **dev**
  env"). They are words people say and read in sentences, in the header
  badge on every page and in page subtitles; monospace in a sentence or an
  11px badge reads as a code sample. Monospace is for values people copy or
  type: keys, paths, fingerprints, repository names, branches, namespaces.
  Use it for those in help text, dialogs and toasts too.
- A region is a `RegionTag` (monospace `text-xs` in a small bordered tag)
  wherever one is shown on its own: tables, pending changes, the pull
  request dialog. The key list's region chips and the form's region toggles
  use the same type, with their state's colors.
- Times are relative with the absolute time in the `title`, through
  `RelativeTime` (a `time dateTime` element): "12s ago", "in 40m", and "just
  now" within a few seconds. That includes dates such as a key's "Valid
  from" and a session's expiry. Absolute times use `formatDateTime`: one
  format, with the hour unpadded ("8:10 PM").

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

## Cards

Cards have `rounded-xl`, a border and a light shadow (none in the dark
theme). Inside a card, sections are separated by a border and padded `px-4`:
header rows `py-3`, everything else `py-4`. Empty states center their
content with `p-10`.

## Buttons

- One primary button per card or dialog, for its main action (Sign in with
  GitHub, Seal, Open pull request). Everything else is `outline` or `ghost`.
- Every size shares one radius. Actions inside cards are `size="sm"` (Seal,
  Open pull request, Docs); page and dialog actions use the default size.
  Buttons stacked in a dialog are the same size and full width.
- Header controls are all `h-9`: the search button, the theme toggle and
  the account menu.
- A button whose label changes while it works keeps its width (`min-w-32`
  on Seal), so it doesn't jump.
- A button that just succeeded may show it for a moment ("Sealed", in the
  success color) before returning to its label.
- Icon-only buttons (theme toggle, copy) have an `aria-label` and a tooltip
  or `title`.
- A disabled button that people will wonder about says why in muted text
  under it, linked with `aria-describedby`; a `title` alone is not enough.
- Destructive or irreversible actions use the `destructive` variant and
  confirm in a dialog that names what will happen.
- Navigation that leaves the app (signing in with GitHub) is a link styled as
  a button, not a `fetch`.

## Forms

Inputs and textareas have an `--input` border, which meets 3:1 against the
page. A field with `aria-invalid` turns its border and focus ring
destructive, and its help text says what is wrong.

## Messages

- A notice in the page is an `Alert` (`components/ui/alert.tsx`): `info`,
  `success`, `warning` or `destructive`, each with its icon and subtle
  background, an optional heading, the text, and optional actions on the
  right. Never build one by hand. Errors that appear after an action take
  `role="alert"`; standing notices take `role="status"` or none.
- Server text shown in an alert or note is a sentence: a capital first
  letter and a full stop (`sentence()` in `lib/utils.ts`, which leaves an
  identifier at the start alone).
- Something that finished away from where people are looking (a change
  removed, changes discarded, a key revoked) gets a toast that names what
  happened: `toast.success` when it did what was asked. A result shown where
  people acted (a seal's status line under the form, its change appearing
  in the cart) needs no toast as well. A toast never carries a secret value,
  and never replaces an error that needs action. Toasts sit top right,
  under the header, clear of the seal form and the cart.
- The end of a flow (a pull request opened) gets a dialog with the way
  forward ("View pull request") and the way back ("Keep sealing").
- Errors from the API show the server's short message in an alert, never a
  stack trace or a raw status code alone. A page that could not load says
  what to do next and links back (a repository that was not found links to
  Secrets).
- Sign-in refusals map each `/login?error=` code to a sentence that says what
  happened and what to do next ("Ask an admin to add you, then sign in
  again.").
- Loading states use `Skeleton` shapes of the content they replace (the
  repository list shows its table's header and three rows), and controls
  that will be there render disabled rather than appearing late.
- Empty states (`EmptyState`) say what is missing, then why and what to do
  about it ("No repositories" / "The GitHub App is not installed…"). A
  filter that matches nothing says so with the filter in quotes ("No file
  matches “billing”.") and offers Clear filter.

## Color

Components use the tokens in `web/src/index.css`, never palette classes
(`text-white`, `bg-blue-500`) and never opacity to dim text or icons
(`opacity-70`, `text-muted-foreground/80`): a dimmed color fails contrast
and is hard to reason about. Muted is `text-muted-foreground`; disabled
controls are the exception, at `opacity-50`. Each meaning has one token:

| Meaning                           | Token                  | Examples                                                                           |
| --------------------------------- | ---------------------- | ---------------------------------------------------------------------------------- |
| Works, done                       | `success`              | Healthy, Env key, sealed, pull request opened                                      |
| Needs attention                   | `warning`              | Missing keys, Seal again, key limit near, refused scope                            |
| Failed, unavailable, irreversible | `destructive`          | Errors, Revoked, Unhealthy, Never checked in, sealing unavailable, unreadable file |
| Pending, informational            | `info`                 | Pending changes, read only, list may be incomplete                                 |
| Selected, pressed                 | `selected` + `primary` | The picked file and key row, chosen regions                                        |
| Action, link, focus               | `primary`, `ring`      | Primary buttons, links, focus rings                                                |
| Neutral                           | `secondary`, `outline` | Counts, Private, Write, capabilities, Active key                                   |

- Status badges and alerts sit on their color's `*-subtle` background
  (`bg-warning-subtle text-warning`); `Badge` and `Alert` do this.
- Selection is a solid edge in `primary` on `bg-selected`, never a tint
  alone.
- The highlighted item of a menu or the palette has a 2px bar in the ring
  color as well as the accent background.
- State never rests on color alone: badges carry a word, and the env badge's
  dot changes shape too (a circle when sealing works, a triangle when some
  clusters are not ready, a square when it is unavailable, a ring while it
  is checked).
- Every pairing meets WCAG AA in both themes: 4.5:1 for text, 3:1 for
  control borders, icons and focus and selection indicators. Check a new
  pairing in both themes before using it.

## Theme and assets

Every screen works in the light and the dark theme; check both. Both use
slate neutrals with a cobalt accent; in the dark theme the primary is a
lighter blue with a navy foreground, since it is a text color there too.
The theme provider always sets `.light` or `.dark` on `<html>`, before the
first paint, with transitions off while it swaps. Until it runs, a
`prefers-color-scheme: dark` block (an exact copy of `.dark`, checked by a
test) gives people who prefer dark a dark first paint, and `index.html`
declares `color-scheme` and a `theme-color` per scheme.

The UI is served with a strict Content Security Policy: scripts only from
the app's own bundle (never inline, never another origin) and no third-party
origins except GitHub avatars. Inline styles are allowed because Radix menus
and dialogs inject them. Bundle fonts and icons (lucide-react). After
changing a screen, open its menus and dialogs and check the browser console
for CSP violations.

## Accessibility

Keep keyboard focus visible, give every control an accessible name, use
`role="alert"` for errors that appear after an action, and keep contrast at
WCAG AA in both themes (see Color).

import { useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { ArrowRight, ChevronRight, FolderGit2, Search } from "lucide-react";
import { reposQueryOptions } from "@/api/queries/repos";
import { sessionsQueryOptions } from "@/api/queries/sessions";
import { extractApiError } from "@/api/client";
import type { Repository } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Kbd } from "@/components/ui/kbd";
import { Skeleton } from "@/components/ui/skeleton";
import { useEnv } from "@/lib/env";
import { useShortcut } from "@/lib/shortcuts";

/** The user's own permission on a repository, as a badge. */
export function AccessBadge({ access }: { access: Repository["access"] }) {
  return access === "write" ? (
    <Badge variant="success">Write</Badge>
  ) : (
    <Badge variant="secondary">Read only</Badge>
  );
}

function plural(n: number, one: string, many: string) {
  return n === 1 ? `1 ${one}` : `${n} ${many}`;
}

/** Repositories with pending changes, to pick up where the user left off. */
function Continue({
  repos,
  pending,
}: {
  repos: Repository[];
  pending: Map<string, number>;
}) {
  const env = useEnv()?.name ?? "";
  const open = repos.filter(
    (r) => (pending.get(r.full_name.toLowerCase()) ?? 0) > 0,
  );
  if (open.length === 0) return null;
  return (
    <section aria-labelledby="continue-heading" className="space-y-2">
      <h2
        id="continue-heading"
        className="text-xs font-semibold tracking-wide text-muted-foreground uppercase"
      >
        Pick up where you left off
      </h2>
      <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {open.map((r) => {
          const count = pending.get(r.full_name.toLowerCase()) ?? 0;
          return (
            <li key={r.full_name}>
              <Link
                to="/$env/secrets/$owner/$repo"
                params={{ env, owner: r.owner, repo: r.name }}
                className="group flex items-center justify-between gap-3 rounded-xl border border-primary/25 bg-primary/5 px-4 py-3 transition-colors hover:bg-primary/10 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none dark:bg-primary/10"
              >
                <span className="min-w-0">
                  <span className="block truncate font-mono text-sm font-medium">
                    {r.full_name}
                  </span>
                  <span className="text-xs text-primary">
                    {plural(count, "pending change", "pending changes")}
                  </span>
                </span>
                <ArrowRight
                  className="h-4 w-4 shrink-0 text-primary transition-transform group-hover:translate-x-0.5"
                  aria-hidden="true"
                />
              </Link>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

/** Says that repositories the user can read may be missing from the list. */
function IncompleteNotice() {
  return (
    <p
      role="status"
      className="rounded-xl border border-dashed px-4 py-3 text-sm text-muted-foreground"
    >
      Some repositories may be missing: GitHub did not answer for all of them in
      time. Reload the page to check the rest.
    </p>
  );
}

/** The repositories page: every repository the user can read. */
export function RepoList() {
  const env = useEnv()?.name ?? "";
  const navigate = useNavigate();
  const { data: list, error, isPending } = useQuery(reposQueryOptions);
  const data = list?.repositories;
  // pending changes per repository; the list works without them
  const { data: sessions } = useQuery(sessionsQueryOptions);
  const pending = new Map(
    (sessions ?? []).map((s) => [
      s.repository.toLowerCase(),
      s.pending_changes,
    ]),
  );
  const [filter, setFilter] = useState("");
  const filterRef = useRef<HTMLInputElement>(null);
  useShortcut("/", () => filterRef.current?.focus());

  const needle = filter.trim().toLowerCase();
  const shown = (data ?? []).filter((r) =>
    r.full_name.toLowerCase().includes(needle),
  );
  const open = (r: Repository) =>
    void navigate({
      to: "/$env/secrets/$owner/$repo",
      params: { env, owner: r.owner, repo: r.name },
    });

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div className="space-y-1">
          <h1 className="text-xl font-semibold tracking-tight">Secrets</h1>
          <p className="text-sm text-muted-foreground">
            Pick a repository to seal values into its SealedSecrets for the{" "}
            <span className="font-medium text-foreground">{env}</span> env.
          </p>
        </div>
        {data && data.length > 0 && (
          <div className="relative w-full sm:w-72">
            <Search
              className="pointer-events-none absolute top-1/2 left-2.5 h-4 w-4 -translate-y-1/2 text-muted-foreground"
              aria-hidden="true"
            />
            <Input
              ref={filterRef}
              type="search"
              name="repository-filter"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && shown[0]) {
                  e.preventDefault();
                  open(shown[0]);
                } else if (e.key === "Escape") {
                  setFilter("");
                }
              }}
              placeholder="Filter repositories"
              aria-label="Filter repositories"
              className="h-9 pr-9 pl-8"
            />
            <Kbd className="pointer-events-none absolute top-1/2 right-2.5 -translate-y-1/2">
              /
            </Kbd>
          </div>
        )}
      </header>

      {isPending ? (
        <div aria-busy="true" aria-label="Loading repositories">
          <Skeleton className="h-48 w-full" />
        </div>
      ) : !data ? (
        <Card role="alert" className="border-destructive/50">
          <CardContent className="p-6 text-sm text-destructive">
            Could not load repositories: {extractApiError(error)}
          </CardContent>
        </Card>
      ) : data.length === 0 && list?.incomplete ? (
        <IncompleteNotice />
      ) : data.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center gap-2 p-10 text-center">
            <FolderGit2
              className="h-8 w-8 text-muted-foreground"
              aria-hidden="true"
            />
            <p className="font-medium">No repositories</p>
            <p className="max-w-md text-sm text-muted-foreground">
              The GitHub App is not installed on any repository you can read.
              Ask an organization owner to install it on the repositories that
              hold your SealedSecrets.
            </p>
          </CardContent>
        </Card>
      ) : (
        <>
          {!needle && <Continue repos={data} pending={pending} />}
          {list?.incomplete && <IncompleteNotice />}
          <section aria-labelledby="all-heading" className="space-y-2">
            <h2
              id="all-heading"
              className="flex items-center justify-between text-xs font-semibold tracking-wide text-muted-foreground uppercase"
            >
              All repositories
              <span className="font-normal normal-case">
                {needle
                  ? `${shown.length} of ${data.length}`
                  : plural(data.length, "repository", "repositories")}
              </span>
            </h2>
            {shown.length === 0 ? (
              <p className="rounded-xl border border-dashed px-4 py-8 text-center text-sm text-muted-foreground">
                No repository matches “{filter.trim()}”.
              </p>
            ) : (
              <div className="overflow-x-auto rounded-xl border bg-card shadow-xs">
                <table className="w-full text-sm">
                  <caption className="sr-only">Repositories</caption>
                  <thead className="border-b border-border bg-muted/40 text-xs tracking-wide text-muted-foreground uppercase">
                    <tr>
                      <th
                        scope="col"
                        className="px-4 py-2.5 text-left font-semibold"
                      >
                        Repository
                      </th>
                      <th
                        scope="col"
                        className="px-4 py-2.5 text-left font-semibold"
                      >
                        Visibility
                      </th>
                      <th
                        scope="col"
                        className="px-4 py-2.5 text-left font-semibold"
                      >
                        Your access
                      </th>
                      <th
                        scope="col"
                        className="px-4 py-2.5 text-left font-semibold"
                      >
                        Default branch
                      </th>
                      <th scope="col" className="w-10 px-4 py-2.5">
                        <span className="sr-only">Open</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {shown.map((r) => {
                      const count = pending.get(r.full_name.toLowerCase());
                      return (
                        <tr
                          key={r.full_name}
                          onClick={() => open(r)}
                          className="group cursor-pointer border-b border-border last:border-0 hover:bg-muted/40"
                        >
                          <th
                            scope="row"
                            className="px-4 py-3 text-left font-mono text-sm font-medium whitespace-nowrap"
                          >
                            <Link
                              to="/$env/secrets/$owner/$repo"
                              params={{ env, owner: r.owner, repo: r.name }}
                              className="hover:underline focus-visible:underline"
                              onClick={(e) => e.stopPropagation()}
                            >
                              {r.full_name}
                            </Link>
                            {count ? (
                              <Badge className="ml-2 align-middle font-sans">
                                {plural(
                                  count,
                                  "pending change",
                                  "pending changes",
                                )}
                              </Badge>
                            ) : null}
                          </th>
                          <td className="px-4 py-3">
                            <Badge variant="outline">
                              {r.private ? "Private" : "Public"}
                            </Badge>
                          </td>
                          <td className="px-4 py-3">
                            <AccessBadge access={r.access} />
                          </td>
                          <td className="px-4 py-3 font-mono text-xs whitespace-nowrap">
                            {r.default_branch}
                          </td>
                          <td className="px-4 py-3 text-muted-foreground">
                            <ChevronRight
                              className="h-4 w-4 transition-transform group-hover:translate-x-0.5"
                              aria-hidden="true"
                            />
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}

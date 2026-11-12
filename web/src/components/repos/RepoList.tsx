import { useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { ArrowRight, ChevronRight, FolderGit2 } from "lucide-react";
import { reposQueryOptions } from "@/api/queries/repos";
import { sessionsQueryOptions } from "@/api/queries/sessions";
import { extractApiError } from "@/api/client";
import type { Repository } from "@/api/types";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { RelativeTime } from "@/components/ui/relative-time";
import { EmptyState } from "@/components/ui/empty-state";
import { FilterInput } from "@/components/ui/filter-input";
import { SectionHeading } from "@/components/ui/section-heading";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useEnv } from "@/lib/env";
import {
  recentItems,
  useRecentRepos,
  type RecentItem,
} from "@/lib/recent-repos";
import { useShortcut } from "@/lib/shortcuts";
import { sentence } from "@/lib/utils";
import { PathLine } from "./FileList";

/** The user's own permission on a repository, as a neutral badge. */
export function AccessBadge({ access }: { access: Repository["access"] }) {
  return access === "write" ? (
    <Badge variant="outline">Write</Badge>
  ) : (
    <Badge variant="secondary">Read Only</Badge>
  );
}

function plural(n: number, one: string, many: string) {
  return n === 1 ? `1 ${one}` : `${n} ${many}`;
}

/**
 * The repositories the user worked in lately, to pick up where they left
 * off: pending changes waiting for a pull request, and the file a value
 * last went into, which the card opens.
 */
function Recent({ items }: { items: RecentItem[] }) {
  const env = useEnv()?.name ?? "";
  if (items.length === 0) return null;
  return (
    <section aria-labelledby="recent-heading" className="space-y-3">
      <SectionHeading id="recent-heading" title="Recent Repositories" />
      <ul className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {items.map(({ repo: r, pending, sealedAt, path }) => (
          <li key={r.full_name}>
            <Link
              to="/$env/secrets/$owner/$repo"
              params={{ env, owner: r.owner, repo: r.name }}
              search={path ? { file: path } : {}}
              className="group flex h-full items-center justify-between gap-3 rounded-xl border bg-card px-4 py-3 shadow-xs transition-colors hover:bg-muted/40 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none dark:shadow-none"
            >
              <span className="min-w-0 flex-1 space-y-1">
                <span className="block truncate font-mono text-sm font-medium">
                  {r.full_name}
                </span>
                {(pending > 0 || sealedAt) && (
                  <span className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
                    {pending > 0 && (
                      <Badge variant="info">
                        {plural(pending, "Pending Change", "Pending Changes")}
                      </Badge>
                    )}
                    {sealedAt && (
                      <span>
                        Sealed{" "}
                        <RelativeTime
                          iso={sealedAt}
                          past
                          describe={(at) =>
                            `You last sealed a value here ${at}`
                          }
                        />
                      </span>
                    )}
                  </span>
                )}
                {path && <PathLine path={path} quiet className="text-xs" />}
              </span>
              <ArrowRight
                className="h-4 w-4 shrink-0 text-muted-foreground transition-transform group-hover:translate-x-0.5"
                aria-hidden="true"
              />
            </Link>
          </li>
        ))}
      </ul>
    </section>
  );
}

/** Says that repositories the user can read may be missing from the list. */
function IncompleteNotice() {
  return (
    <Alert variant="info" role="status">
      Some repositories may be missing: GitHub did not answer for all of them in
      time. Reload the page to check the rest.
    </Alert>
  );
}

const COLUMNS = ["Repository", "Visibility", "Your Access", "Default Branch"];

/** The repositories table's shape while it loads. */
function TableSkeleton() {
  return (
    <div
      className="space-y-3"
      aria-busy="true"
      aria-label="Loading repositories"
    >
      <Skeleton className="h-6 w-40" />
      <Table>
        <TableHeader>
          <tr>
            {COLUMNS.map((c) => (
              <TableHead key={c}>{c}</TableHead>
            ))}
            <TableHead className="w-10" />
          </tr>
        </TableHeader>
        <tbody>
          {[0, 1, 2].map((i) => (
            <TableRow key={i} className="h-12">
              <TableCell>
                <Skeleton className="h-4 w-48" />
              </TableCell>
              <TableCell>
                <Skeleton className="h-4 w-14" />
              </TableCell>
              <TableCell>
                <Skeleton className="h-4 w-16" />
              </TableCell>
              <TableCell>
                <Skeleton className="h-4 w-12" />
              </TableCell>
              <TableCell />
            </TableRow>
          ))}
        </tbody>
      </Table>
    </div>
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
  const recent = useRecentRepos();
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
        {/* the filter holds its place while the list loads */}
        {(isPending || (data && data.length > 0)) && (
          <FilterInput
            inputRef={filterRef}
            className="w-full sm:w-72"
            name="repository-filter"
            value={filter}
            onValueChange={setFilter}
            disabled={isPending}
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
          />
        )}
      </header>

      {isPending ? (
        <TableSkeleton />
      ) : !data ? (
        <Alert
          variant="destructive"
          role="alert"
          heading="Could Not Load Repositories"
        >
          {sentence(extractApiError(error))}
        </Alert>
      ) : data.length === 0 && list?.incomplete ? (
        <IncompleteNotice />
      ) : data.length === 0 ? (
        <EmptyState icon={FolderGit2} title="No Repositories">
          The GitHub App is not installed on any repository you can read. Ask an
          organization owner to install it on the repositories that hold your
          SealedSecrets.
        </EmptyState>
      ) : (
        <>
          {!needle && <Recent items={recentItems(data, pending, recent)} />}
          {list?.incomplete && <IncompleteNotice />}
          <section aria-labelledby="all-heading" className="space-y-3">
            <SectionHeading
              id="all-heading"
              title="All Repositories"
              count={
                needle
                  ? `${shown.length} of ${data.length}`
                  : plural(data.length, "repository", "repositories")
              }
            />
            {shown.length === 0 ? (
              <div className="space-y-3 rounded-xl border border-dashed px-4 py-8 text-center text-sm text-muted-foreground">
                <p>No repository matches “{filter.trim()}”.</p>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setFilter("");
                    filterRef.current?.focus();
                  }}
                >
                  Clear Filter
                </Button>
              </div>
            ) : (
              <Table>
                <caption className="sr-only">Repositories</caption>
                <TableHeader>
                  <tr>
                    {COLUMNS.map((c) => (
                      <TableHead key={c}>{c}</TableHead>
                    ))}
                    <TableHead className="w-10">
                      <span className="sr-only">Open</span>
                    </TableHead>
                  </tr>
                </TableHeader>
                <tbody>
                  {shown.map((r) => {
                    const count = pending.get(r.full_name.toLowerCase());
                    return (
                      <TableRow
                        key={r.full_name}
                        onClick={() => open(r)}
                        className="group cursor-pointer hover:bg-muted/40 has-[a:focus-visible]:bg-muted/40"
                      >
                        <th
                          scope="row"
                          className="px-4 py-3 text-left font-mono text-sm font-medium whitespace-nowrap"
                        >
                          <Link
                            to="/$env/secrets/$owner/$repo"
                            params={{ env, owner: r.owner, repo: r.name }}
                            className="rounded-sm hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                            onClick={(e) => e.stopPropagation()}
                          >
                            {r.full_name}
                          </Link>
                          {count ? (
                            <Badge
                              variant="info"
                              className="ml-2 align-middle font-sans"
                            >
                              {plural(
                                count,
                                "Pending Change",
                                "Pending Changes",
                              )}
                            </Badge>
                          ) : null}
                        </th>
                        <TableCell>
                          <Badge variant="outline">
                            {r.private ? "Private" : "Public"}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <AccessBadge access={r.access} />
                        </TableCell>
                        <TableCell className="font-mono text-xs whitespace-nowrap">
                          {r.default_branch}
                        </TableCell>
                        <TableCell className="text-muted-foreground">
                          <ChevronRight
                            className="h-4 w-4 transition-transform group-hover:translate-x-0.5"
                            aria-hidden="true"
                          />
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </tbody>
              </Table>
            )}
          </section>
        </>
      )}
    </div>
  );
}

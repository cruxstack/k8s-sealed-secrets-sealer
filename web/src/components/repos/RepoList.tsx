import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ChevronRight, FolderGit2 } from "lucide-react";
import { reposQueryOptions } from "@/api/queries/repos";
import { extractApiError } from "@/api/client";
import type { Repository } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

/** The user's own permission on a repository, as a badge. */
export function AccessBadge({ access }: { access: Repository["access"] }) {
  return access === "write" ? (
    <Badge variant="success">Write</Badge>
  ) : (
    <Badge variant="secondary">Read only</Badge>
  );
}

/** The repositories page: every repository the user can read. */
export function RepoList() {
  const { data, error, isPending } = useQuery(reposQueryOptions);

  return (
    <section aria-labelledby="repos-heading" className="space-y-3">
      <div className="flex items-baseline justify-between gap-4">
        <h1 id="repos-heading" className="text-lg font-semibold">
          Repositories
        </h1>
        <p className="text-xs text-muted-foreground">
          Repositories the GitHub App can see that you can read
        </p>
      </div>

      {isPending ? (
        <div aria-busy="true" aria-label="Loading repositories">
          <Skeleton className="h-48 w-full" />
        </div>
      ) : error && !data ? (
        <Card role="alert" className="border-destructive/50">
          <CardContent className="p-6 text-sm text-destructive">
            Could not load repositories: {extractApiError(error)}
          </CardContent>
        </Card>
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
        <div className="overflow-x-auto rounded-xl border bg-card">
          <table className="w-full text-sm">
            <caption className="sr-only">Repositories</caption>
            <thead className="border-b border-border bg-muted/50 text-xs uppercase tracking-wide text-muted-foreground">
              <tr>
                <th scope="col" className="px-4 py-3 text-left font-semibold">
                  Repository
                </th>
                <th scope="col" className="px-4 py-3 text-left font-semibold">
                  Visibility
                </th>
                <th scope="col" className="px-4 py-3 text-left font-semibold">
                  Your access
                </th>
                <th scope="col" className="px-4 py-3 text-left font-semibold">
                  Default branch
                </th>
                <th scope="col" className="w-10 px-4 py-3">
                  <span className="sr-only">Open</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {data.map((r) => (
                <tr
                  key={r.full_name}
                  className="group border-b border-border last:border-0 hover:bg-muted/40"
                >
                  <th
                    scope="row"
                    className="px-4 py-3 text-left font-mono text-sm font-medium whitespace-nowrap"
                  >
                    <Link
                      to="/repos/$owner/$repo"
                      params={{ owner: r.owner, repo: r.name }}
                      className="hover:underline focus-visible:underline"
                    >
                      {r.full_name}
                    </Link>
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
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

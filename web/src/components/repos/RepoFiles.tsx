import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { FileSearch, FileWarning, Lock } from "lucide-react";
import { repoFilesQueryOptions } from "@/api/queries/repos";
import { extractApiError } from "@/api/client";
import type { RepositoryFile, SealedSecretDocument } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuth } from "@/lib/auth";
import { AccessBadge } from "./RepoList";

function Dash() {
  return (
    <span className="text-muted-foreground" aria-label="none">
      —
    </span>
  );
}

const SCOPE_LABELS: Record<SealedSecretDocument["scope"], string> = {
  strict: "Strict",
  "namespace-wide": "Namespace-wide",
  "cluster-wide": "Cluster-wide",
};

function DocumentRow({ doc }: { doc: SealedSecretDocument }) {
  return (
    <tr className="border-b border-border last:border-0 align-top">
      <th
        scope="row"
        className="truncate px-4 py-3 text-left font-mono text-sm font-medium whitespace-nowrap"
        title={`${doc.namespace}/${doc.name}`}
      >
        {doc.namespace || <Dash />}
        <span className="text-muted-foreground">/</span>
        {doc.name || <Dash />}
      </th>
      <td className="px-4 py-3 whitespace-nowrap">{doc.region || <Dash />}</td>
      <td className="px-4 py-3">
        <Badge
          variant={doc.scope === "cluster-wide" ? "destructive" : "outline"}
        >
          {SCOPE_LABELS[doc.scope]}
        </Badge>
      </td>
      <td className="px-4 py-3">
        {doc.keys.length > 0 ? (
          <ul className="flex flex-wrap gap-1" aria-label="Keys">
            {doc.keys.map((k) => (
              <li key={k}>
                <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                  {k}
                </code>
              </li>
            ))}
          </ul>
        ) : (
          <span className="text-xs text-muted-foreground">No keys yet</span>
        )}
      </td>
      <td className="px-4 py-3 text-xs">
        {doc.problem ? (
          <div className="space-y-1">
            <Badge variant="warning">Can't seal</Badge>
            <p className="max-w-sm text-muted-foreground">{doc.problem}</p>
          </div>
        ) : (
          <Badge variant="success">Ready</Badge>
        )}
      </td>
    </tr>
  );
}

function FileCard({ file }: { file: RepositoryFile }) {
  const docs = file.documents ?? [];
  return (
    <section
      aria-label={file.path}
      className="overflow-hidden rounded-xl border bg-card"
    >
      <div className="flex items-baseline justify-between gap-4 border-b border-border px-4 py-3">
        <h2
          className="truncate font-mono text-sm font-semibold"
          title={file.path}
        >
          {file.path}
        </h2>
        {!file.error && (
          <span className="shrink-0 text-xs text-muted-foreground">
            {docs.length === 1 ? "1 document" : `${docs.length} documents`}
          </span>
        )}
      </div>
      {file.error ? (
        <p className="flex items-center gap-2 px-4 py-3 text-sm text-warning">
          <FileWarning className="h-4 w-4 shrink-0" aria-hidden="true" />
          Could not read this file: {file.error}
        </p>
      ) : (
        <div className="overflow-x-auto">
          {/* fixed widths, so columns line up from one file to the next */}
          <table className="w-full min-w-[56rem] table-fixed text-sm">
            <caption className="sr-only">
              SealedSecret documents in {file.path}
            </caption>
            <colgroup>
              <col className="w-[36%]" />
              <col className="w-[9%]" />
              <col className="w-[14%]" />
              <col className="w-[18%]" />
              <col className="w-[23%]" />
            </colgroup>
            <thead className="border-b border-border bg-muted/50 text-xs uppercase tracking-wide text-muted-foreground">
              <tr>
                <th scope="col" className="px-4 py-2 text-left font-semibold">
                  Namespace / name
                </th>
                <th scope="col" className="px-4 py-2 text-left font-semibold">
                  Region
                </th>
                <th scope="col" className="px-4 py-2 text-left font-semibold">
                  Scope
                </th>
                <th scope="col" className="px-4 py-2 text-left font-semibold">
                  Keys
                </th>
                <th scope="col" className="px-4 py-2 text-left font-semibold">
                  Status
                </th>
              </tr>
            </thead>
            <tbody>
              {docs.map((d) => (
                <DocumentRow key={d.index} doc={d} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

/** A repository's SealedSecret files for this env. */
export function RepoFiles({ owner, repo }: { owner: string; repo: string }) {
  const { env } = useAuth();
  const { data, error, isPending } = useQuery(
    repoFilesQueryOptions(owner, repo),
  );

  return (
    <div className="space-y-6">
      <nav aria-label="Breadcrumb" className="text-sm text-muted-foreground">
        <ol className="flex items-center gap-1.5">
          <li>
            <Link to="/repos" className="hover:text-foreground hover:underline">
              Repositories
            </Link>
          </li>
          <li aria-hidden="true">/</li>
          <li aria-current="page" className="font-mono text-foreground">
            {owner}/{repo}
          </li>
        </ol>
      </nav>

      {isPending ? (
        <div className="space-y-4" aria-busy="true" aria-label="Loading files">
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-48 w-full" />
        </div>
      ) : error && !data ? (
        <Card role="alert" className="border-destructive/50">
          <CardContent className="p-6 text-sm text-destructive">
            Could not load this repository: {extractApiError(error)}
          </CardContent>
        </Card>
      ) : (
        <>
          <header className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="font-mono text-lg font-semibold">
                {data.repository.full_name}
              </h1>
              <Badge variant="outline">
                {data.repository.private ? "Private" : "Public"}
              </Badge>
              <AccessBadge access={data.repository.access} />
            </div>
            <p className="text-sm text-muted-foreground">
              SealedSecrets for the{" "}
              <span className="font-medium text-foreground">{env}</span> env on{" "}
              <code className="font-mono text-xs">{data.branch}</code> at{" "}
              <code className="font-mono text-xs" title={data.commit}>
                {data.commit.slice(0, 7)}
              </code>
            </p>
          </header>

          {data.repository.access !== "write" && (
            <p className="flex items-center gap-2 rounded-lg border border-border bg-muted/40 px-4 py-3 text-sm">
              <Lock className="h-4 w-4 shrink-0" aria-hidden="true" />
              You can read this repository but not write to it. Sealing needs
              write access on GitHub.
            </p>
          )}
          {data.truncated && (
            <p
              role="status"
              className="rounded-lg border border-warning/40 bg-warning/10 px-4 py-3 text-sm"
            >
              This repository is too large to search completely; some files may
              be missing.
            </p>
          )}

          {data.files.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center gap-2 p-10 text-center">
                <FileSearch
                  className="h-8 w-8 text-muted-foreground"
                  aria-hidden="true"
                />
                <p className="font-medium">No SealedSecrets for {env}</p>
                <p className="max-w-md text-sm text-muted-foreground">
                  No file on {data.branch} has a SealedSecret annotated for this
                  env. Files searched:{" "}
                  {data.file_globs.map((g, i) => (
                    <span key={g}>
                      {i > 0 && ", "}
                      <code className="font-mono text-xs">{g}</code>
                    </span>
                  ))}
                  .
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              {data.files.map((f) => (
                <FileCard key={f.path} file={f} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

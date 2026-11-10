import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import {
  CircleSlash,
  ExternalLink,
  FileSearch,
  FileWarning,
  GitBranch,
  Lock,
  X,
} from "lucide-react";
import { extractApiError } from "@/api/client";
import { repoFilesQueryOptions } from "@/api/queries/repos";
import { sessionQueryOptions } from "@/api/queries/sessions";
import { statusQueryOptions } from "@/api/queries/status";
import type { PullRequest, RepositoryFile } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useEnv } from "@/lib/env";
import { safeHttpUrl } from "@/lib/utils";
import { FileList, fileStatus } from "./FileList";
import { FilePanel } from "./FilePanel";
import { OpenedDialog, PendingChanges } from "./PendingChanges";
import { AccessBadge } from "./RepoList";

/** The file to show when none is chosen: the first one values fit in. */
function defaultFile(files: RepositoryFile[]): RepositoryFile | undefined {
  return files.find((f) => fileStatus(f) === "ready") ?? files[0];
}

/** Says a pull request was opened, until dismissed. */
function OpenedBanner({
  pr,
  onDismiss,
}: {
  pr: PullRequest;
  onDismiss: () => void;
}) {
  const url = safeHttpUrl(pr.url);
  return (
    <div
      role="status"
      aria-label="Pull request opened"
      className="flex flex-col gap-3 rounded-xl border border-success/40 bg-success/10 px-4 py-3 text-sm sm:flex-row sm:items-center sm:justify-between"
    >
      <p>
        Opened pull request <span className="font-semibold">#{pr.number}</span>:{" "}
        {pr.title}.{" "}
        <span className="text-muted-foreground">
          Branch <code className="font-mono text-xs">{pr.branch}</code>.
        </span>
      </p>
      <div className="flex shrink-0 items-center gap-1">
        {url && (
          <Button asChild variant="outline" size="sm">
            <a href={url} target="_blank" rel="noopener noreferrer">
              View pull request
              <ExternalLink className="ml-1.5 h-3.5 w-3.5" aria-hidden="true" />
            </a>
          </Button>
        )}
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8"
          aria-label="Dismiss"
          onClick={onDismiss}
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </Button>
      </div>
    </div>
  );
}

function WorkspaceSkeleton() {
  return (
    <div
      className="grid grid-cols-1 gap-6 lg:grid-cols-[20rem_minmax(0,1fr)]"
      aria-busy="true"
      aria-label="Loading files"
    >
      <div className="space-y-4">
        <Skeleton className="h-80 w-full" />
        <Skeleton className="h-36 w-full" />
      </div>
      <Skeleton className="h-[30rem] w-full" />
    </div>
  );
}

/**
 * A repository's sealing workspace: its SealedSecret files for the env and
 * the pending changes waiting for a pull request on the left, and the
 * chosen file with its seal form on the right. With an open session the
 * files are shown at the session's base commit.
 */
export function RepoWorkspace({
  owner,
  repo,
  selected,
  onSelect,
}: {
  owner: string;
  repo: string;
  /** The chosen file's path, from the URL. */
  selected: string | undefined;
  onSelect: (path: string) => void;
}) {
  const env = useEnv()?.name ?? "";
  const { data: status } = useQuery(statusQueryOptions);
  const sessionQuery = useQuery(sessionQueryOptions(owner, repo));
  const session = sessionQuery.data ?? null;
  const { data, error, isPending } = useQuery({
    ...repoFilesQueryOptions(owner, repo, session?.commit),
    // wait for the session, so the files are read at its commit
    enabled: !sessionQuery.isPending,
  });
  const [sealBusy, setSealBusy] = useState(false);
  const [opened, setOpened] = useState<PullRequest | null>(null);
  const [celebrate, setCelebrate] = useState(false);
  // after the user picks a file, its form takes focus; not on page load
  const [picked, setPicked] = useState(false);
  // a pull request ends the session: the form starts afresh
  const [round, setRound] = useState(0);
  const pick = (path: string) => {
    setPicked(true);
    onSelect(path);
  };

  const files = data?.files ?? [];
  const chosen = files.find((f) => f.path === selected);
  const current = chosen ?? defaultFile(files);
  const canWrite = data?.repository.access === "write";
  const changes = session?.changes ?? [];

  return (
    <div className="space-y-6">
      <header className="space-y-1.5">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <nav aria-label="Breadcrumb" className="min-w-0">
            <ol className="flex flex-wrap items-baseline gap-x-2 text-xl tracking-tight">
              <li>
                <Link
                  to="/$env/secrets"
                  params={{ env }}
                  className="font-semibold text-muted-foreground hover:text-foreground hover:underline"
                >
                  Secrets
                </Link>
              </li>
              <li aria-hidden="true" className="text-muted-foreground/60">
                /
              </li>
              <li aria-current="page" className="min-w-0">
                <h1 className="font-mono font-semibold break-all">
                  {data?.repository.full_name ?? `${owner}/${repo}`}
                </h1>
              </li>
            </ol>
          </nav>
          {data && (
            <span className="flex items-center gap-2">
              <Badge variant="outline">
                {data.repository.private ? "Private" : "Public"}
              </Badge>
              <AccessBadge access={data.repository.access} />
            </span>
          )}
        </div>
        {data && (
          <p className="flex flex-wrap items-center gap-1.5 text-sm text-muted-foreground">
            SealedSecrets for the{" "}
            <span className="font-medium text-foreground">{env}</span> env on
            <GitBranch className="h-3.5 w-3.5" aria-hidden="true" />
            <code className="font-mono text-xs">{data.branch}</code> at{" "}
            <code className="font-mono text-xs" title={data.commit}>
              {data.commit.slice(0, 7)}
            </code>
          </p>
        )}
      </header>

      {isPending ? (
        <WorkspaceSkeleton />
      ) : error && !data ? (
        <div className="grid grid-cols-1 items-start gap-6 lg:grid-cols-[20rem_minmax(0,1fr)]">
          {/* pending changes stay reachable, so they can still be discarded
              when the commit they are based on is gone */}
          {session && (
            <PendingChanges
              owner={owner}
              repo={repo}
              session={session}
              onSelectFile={pick}
              onOpened={(pr) => {
                setOpened(pr);
                setCelebrate(true);
              }}
            />
          )}
          <Card
            role="alert"
            className="border-destructive/50 lg:col-start-2 lg:row-start-1"
          >
            <CardContent className="space-y-1 p-6 text-sm">
              <p className="text-destructive">
                Could not load this repository: {extractApiError(error)}
              </p>
              {session && (
                <p className="text-muted-foreground">
                  The files are read at the commit your pending changes are
                  based on,{" "}
                  <code className="font-mono text-xs">
                    {session.commit.slice(0, 7)}
                  </code>
                  . If it is gone from {session.branch}, discard the changes to
                  start again from its head.
                </p>
              )}
            </CardContent>
          </Card>
        </div>
      ) : (
        <>
          {opened && (
            <OpenedBanner pr={opened} onDismiss={() => setOpened(null)} />
          )}
          {!canWrite && (
            <p className="flex items-center gap-2 rounded-xl border border-border bg-muted/40 px-4 py-3 text-sm">
              <Lock className="h-4 w-4 shrink-0" aria-hidden="true" />
              You can read this repository but not write to it. Sealing needs
              write access on GitHub.
            </p>
          )}
          {canWrite && status?.sealing === "unavailable" && (
            <p
              role="status"
              className="flex items-start gap-2 rounded-xl border border-destructive/40 bg-destructive/5 px-4 py-3 text-sm"
            >
              <CircleSlash
                className="mt-0.5 h-4 w-4 shrink-0 text-destructive"
                aria-hidden="true"
              />
              <span>
                Sealing is unavailable in {env} right now: {status.message}{" "}
                <span className="text-muted-foreground">
                  You can look around, but seals fail until its clusters are
                  back.
                </span>
              </span>
            </p>
          )}
          {data.truncated && (
            <p
              role="status"
              className="rounded-xl border border-warning/40 bg-warning/10 px-4 py-3 text-sm"
            >
              This repository is too large to search completely; some files may
              be missing.
            </p>
          )}

          {files.length === 0 ? (
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
            <div className="grid grid-cols-1 items-start gap-6 lg:grid-cols-[20rem_minmax(0,1fr)]">
              {/* the files and the pending changes stay in view while the
                  page scrolls; the file list scrolls on its own */}
              <aside className="flex min-w-0 flex-col gap-4 lg:sticky lg:top-0 lg:max-h-[calc(100vh-7.5rem)]">
                <FileList
                  files={files}
                  selected={current?.path}
                  changes={changes}
                  globs={data.file_globs}
                  onSelect={pick}
                />
                {canWrite && (
                  <PendingChanges
                    owner={owner}
                    repo={repo}
                    session={session}
                    sealing={sealBusy}
                    onSelectFile={pick}
                    onOpened={(pr) => {
                      setOpened(pr);
                      setCelebrate(true);
                      setRound((r) => r + 1);
                    }}
                  />
                )}
              </aside>
              <div className="min-w-0 space-y-6">
                {selected && !chosen && (
                  <p
                    role="status"
                    className="flex items-start gap-2 rounded-xl border border-warning/40 bg-warning/10 px-4 py-3 text-sm"
                  >
                    <FileWarning
                      className="mt-0.5 h-4 w-4 shrink-0 text-warning"
                      aria-hidden="true"
                    />
                    <span>
                      <code className="font-mono">{selected}</code> is not among
                      this repository's SealedSecret files for {env}.
                    </span>
                  </p>
                )}
                {current && (
                  <FilePanel
                    owner={owner}
                    repo={repo}
                    env={env}
                    file={current}
                    commit={data.commit}
                    session={session}
                    canWrite={canWrite}
                    onBusyChange={setSealBusy}
                    focusForm={picked}
                    round={round}
                  />
                )}
              </div>
            </div>
          )}
        </>
      )}
      <OpenedDialog
        pr={celebrate ? opened : null}
        onClose={() => setCelebrate(false)}
      />
    </div>
  );
}

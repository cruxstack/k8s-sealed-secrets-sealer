import { useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ExternalLink, FileSearch, GitBranch, Lock, X } from "lucide-react";
import { toApiError } from "@/api/client";
import { repoFilesQueryOptions } from "@/api/queries/repos";
import { sessionQueryOptions } from "@/api/queries/sessions";
import { statusQueryOptions } from "@/api/queries/status";
import type { PullRequest, RepositoryFile, SealSession } from "@/api/types";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { useEnv } from "@/lib/env";
import { safeHttpUrl, sentence } from "@/lib/utils";
import { FileList, fileStatus } from "./FileList";
import { FilePanel } from "./FilePanel";
import { OpenedDialog, PendingChanges } from "./PendingChanges";
import { AccessBadge } from "./RepoList";
import { useFileReseal } from "./ResealFile";

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
    <Alert
      variant="success"
      role="status"
      aria-label="Pull request opened"
      action={
        <>
          {url && (
            <Button asChild variant="outline" size="sm">
              <a href={url} target="_blank" rel="noopener noreferrer">
                View Pull Request
                <ExternalLink
                  className="ml-1.5 h-3.5 w-3.5"
                  aria-hidden="true"
                />
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
        </>
      }
    >
      Opened pull request <span className="font-semibold">#{pr.number}</span>:{" "}
      {pr.title}.{" "}
      <span className="text-muted-foreground">
        Branch <code className="font-mono text-xs">{pr.branch}</code>.
      </span>
    </Alert>
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
 * The repository could not be read: why, and the way back to the list. A
 * session's pending changes stay reachable below, so they can still be
 * discarded when the commit they are based on is gone.
 */
function LoadError({
  name,
  error,
  session,
  children,
}: {
  name: string;
  error: unknown;
  session: SealSession | null;
  children?: ReactNode;
}) {
  const env = useEnv()?.name ?? "";
  const { status, message } = toApiError(error);
  const missing = status === 404 && !session;
  return (
    <div className="space-y-6">
      <Alert
        variant="destructive"
        role="alert"
        heading={
          missing ? "Repository Not Found" : "Could Not Load This Repository"
        }
        action={
          <Button asChild variant="outline" size="sm">
            <Link to="/$env/secrets" params={{ env }}>
              Back to Secrets
            </Link>
          </Button>
        }
      >
        {missing ? (
          <>
            <code className="font-mono text-xs [overflow-wrap:anywhere]">
              {name}
            </code>{" "}
            doesn't exist, you can't read it on GitHub, or the Sealer GitHub App
            isn't installed on it.
          </>
        ) : status === 404 ? null : (
          `${sentence(message)} `
        )}
        {session && (
          <>
            The files are read at the commit your pending changes are based on,{" "}
            <code className="font-mono text-xs">
              {session.commit.slice(0, 7)}
            </code>
            . If it is gone from {session.branch}, discard the changes to start
            again from its head.
          </>
        )}
      </Alert>
      {children && <div className="lg:w-80">{children}</div>}
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
  const envAccess = useEnv();
  const env = envAccess?.name ?? "";
  const { data: status } = useQuery(statusQueryOptions);
  // "Reseal all" runs a file at a time, whichever file is shown
  const resealer = useFileReseal(owner, repo);
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
  const name = data?.repository.full_name ?? `${owner}/${repo}`;

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
              <li aria-hidden="true" className="text-muted-foreground">
                /
              </li>
              <li aria-current="page" className="min-w-0">
                <h1 className="font-mono font-semibold break-all">{name}</h1>
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
          <p className="text-sm text-muted-foreground">
            SealedSecrets for the{" "}
            <span className="font-medium text-foreground">{env}</span> env on{" "}
            <span className="inline-flex items-center gap-1 whitespace-nowrap">
              <GitBranch className="h-3.5 w-3.5" aria-hidden="true" />
              <code className="font-mono text-xs">{data.branch}</code>
            </span>{" "}
            at{" "}
            <code className="font-mono text-xs" title={data.commit}>
              {data.commit.slice(0, 7)}
            </code>
          </p>
        )}
      </header>

      {isPending ? (
        <WorkspaceSkeleton />
      ) : error && !data ? (
        <LoadError name={name} error={error} session={session}>
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
        </LoadError>
      ) : (
        <>
          {opened && (
            <OpenedBanner pr={opened} onDismiss={() => setOpened(null)} />
          )}
          {!canWrite && (
            <Alert variant="info" icon={Lock}>
              You can read this repository but not write to it. Sealing needs
              write access on GitHub.
            </Alert>
          )}
          {canWrite && status?.sealing === "unavailable" && (
            <Alert
              variant="destructive"
              role="status"
              heading={`Can't Seal in ${env} Right Now`}
            >
              {sentence(status.message)} You can still look around.
            </Alert>
          )}
          {data.truncated && (
            <Alert variant="info" role="status">
              This repository is too large to search completely, so some files
              may be missing.
            </Alert>
          )}

          {files.length === 0 ? (
            <EmptyState icon={FileSearch} title={`No SealedSecrets for ${env}`}>
              No file on {data.branch} has a SealedSecret annotated for this
              env. Files searched:{" "}
              {data.file_globs.map((g, i) => (
                <span key={g}>
                  {i > 0 && ", "}
                  <code className="font-mono text-xs">{g}</code>
                </span>
              ))}
              .
            </EmptyState>
          ) : (
            <div className="grid grid-cols-1 items-start gap-6 lg:grid-cols-[20rem_minmax(0,1fr)]">
              {/* the files and the pending changes stay in view while the
                  page scrolls, clear of the header; the file list scrolls
                  on its own */}
              <aside className="flex min-w-0 flex-col gap-4 lg:sticky lg:top-6 lg:max-h-[calc(100vh-6.5rem)]">
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
                    resealing={resealer.state.phase === "running"}
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
                  <Alert variant="warning" role="status">
                    <code className="font-mono text-xs">{selected}</code> is not
                    among this repository's SealedSecret files for {env}.
                  </Alert>
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
                    resealer={envAccess?.admin ? resealer : undefined}
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

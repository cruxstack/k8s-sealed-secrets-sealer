import type { ReactNode } from "react";
import { FileWarning, Info } from "lucide-react";
import type {
  RepositoryFile,
  SealSession,
  SealedSecretDocument,
} from "@/api/types";
import { CopyButton } from "@/components/fleet/CopyButton";
import { Badge } from "@/components/ui/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { FilePath, fileStatus } from "./FileList";
import { SealForm } from "./SealForm";

const SCOPES: Record<
  SealedSecretDocument["scope"],
  { label: string; detail: string }
> = {
  strict: {
    label: "Strict",
    detail: "Decrypts only into a Secret with this exact name and namespace.",
  },
  "namespace-wide": {
    label: "Namespace-wide",
    detail: "Decrypts into a Secret of any name in this namespace.",
  },
  "cluster-wide": {
    label: "Cluster-wide",
    detail:
      "Would decrypt into any namespace, so anyone able to create a SealedSecret could read it. Not allowed here.",
  },
};

function Dash() {
  return (
    <span className="text-muted-foreground" aria-label="none">
      —
    </span>
  );
}

function ScopeBadge({ scope }: { scope: SealedSecretDocument["scope"] }) {
  const s = SCOPES[scope];
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          className="rounded-md focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          aria-label={`${s.label} scope: ${s.detail}`}
        >
          <Badge
            variant={scope === "cluster-wide" ? "destructive" : "outline"}
            className="cursor-help"
          >
            {s.label}
            <Info className="h-3 w-3 opacity-60" aria-hidden="true" />
          </Badge>
        </button>
      </TooltipTrigger>
      <TooltipContent side="top">
        {s.detail} The scope comes from the document's annotations and cannot be
        changed here.
      </TooltipContent>
    </Tooltip>
  );
}

/** A document's keys, with values waiting in this session marked. */
function Keys({ keys, pending }: { keys: string[]; pending: Set<string> }) {
  const all = [...new Set([...keys, ...pending])].sort();
  if (all.length === 0) {
    return <span className="text-xs text-muted-foreground">No keys yet</span>;
  }
  return (
    <ul className="flex flex-wrap gap-1" aria-label="Keys">
      {all.map((k) => {
        const isPending = pending.has(k);
        const replaces = isPending && keys.includes(k);
        return (
          <li key={k}>
            <code
              className={cn(
                "inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 font-mono text-xs",
                isPending
                  ? "bg-primary/10 text-primary ring-1 ring-primary/25 dark:bg-primary/20"
                  : "bg-muted",
              )}
              title={
                isPending
                  ? replaces
                    ? "A new value is pending"
                    : "Pending: not in the file yet"
                  : undefined
              }
            >
              {k}
              {isPending && (
                <span className="font-sans text-[10px] font-semibold uppercase">
                  {replaces ? "new value" : "new"}
                </span>
              )}
            </code>
          </li>
        );
      })}
    </ul>
  );
}

function Panel({
  file,
  aside,
  children,
}: {
  file: RepositoryFile;
  aside?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section
      aria-label={file.path}
      className="overflow-hidden rounded-xl border bg-card shadow-xs"
    >
      <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
        <div className="min-w-0 space-y-1">
          <h2 className="flex items-center gap-1 text-[15px] leading-6">
            <FilePath path={file.path} />
            <CopyButton value={file.path} label="file path" />
          </h2>
          {aside}
        </div>
      </div>
      {children}
    </section>
  );
}

/**
 * The selected file: its SealedSecret documents for the env and, for people
 * who can write to the repository, the form that seals a value into all of
 * them.
 */
export function FilePanel({
  owner,
  repo,
  env,
  file,
  commit,
  session,
  canWrite,
  onBusyChange,
  focusForm = false,
  round = 0,
}: {
  owner: string;
  repo: string;
  env: string;
  file: RepositoryFile;
  /** The commit the files are shown at. */
  commit: string;
  session: SealSession | null;
  canWrite: boolean;
  onBusyChange: (busy: boolean) => void;
  /** Focus the seal form's key: the user just picked this file. */
  focusForm?: boolean;
  /** Changes when the session ends, to start the seal form afresh. */
  round?: number;
}) {
  const status = fileStatus(file);
  const docs = file.documents ?? [];
  const pending = new Set(
    (session?.changes ?? [])
      .filter((c) => c.path === file.path)
      .map((c) => c.key),
  );

  if (status === "unreadable") {
    return (
      <Panel file={file}>
        <p className="flex items-center gap-2 px-5 py-4 text-sm text-warning">
          <FileWarning className="h-4 w-4 shrink-0" aria-hidden="true" />
          Could not read this file: {file.error}
        </p>
      </Panel>
    );
  }

  return (
    <Panel
      file={file}
      aside={
        <p className="text-xs text-muted-foreground">
          {docs.length === 1
            ? `1 SealedSecret for the ${env} env`
            : `${docs.length} SealedSecrets for the ${env} env`}
        </p>
      }
    >
      <div className="overflow-x-auto">
        <table className="w-full min-w-[40rem] text-sm">
          <caption className="sr-only">
            SealedSecret documents in {file.path}
          </caption>
          <thead className="border-b border-border bg-muted/40 text-xs tracking-wide text-muted-foreground uppercase">
            <tr>
              <th scope="col" className="px-5 py-2 text-left font-semibold">
                Namespace / name
              </th>
              <th scope="col" className="px-3 py-2 text-left font-semibold">
                Region
              </th>
              <th scope="col" className="px-3 py-2 text-left font-semibold">
                Scope
              </th>
              <th
                scope="col"
                className="px-3 py-2 pr-5 text-left font-semibold"
              >
                Keys
              </th>
            </tr>
          </thead>
          <tbody>
            {docs.map((d) => (
              <tr
                key={d.index}
                className="border-b border-border align-top last:border-0"
              >
                <th
                  scope="row"
                  className="px-5 py-2.5 text-left font-mono text-[13px] font-medium whitespace-nowrap"
                >
                  {d.namespace || <Dash />}
                  <span className="text-muted-foreground">/</span>
                  {d.name || <Dash />}
                  {d.problem && (
                    <p className="mt-1 max-w-md font-sans text-xs font-normal whitespace-normal text-warning">
                      {d.problem}
                    </p>
                  )}
                </th>
                <td className="px-3 py-2.5 whitespace-nowrap">
                  {d.region || <Dash />}
                </td>
                <td className="px-3 py-2.5">
                  <ScopeBadge scope={d.scope} />
                </td>
                <td className="px-3 py-2.5 pr-5">
                  <Keys
                    keys={d.keys}
                    pending={d.problem ? new Set() : pending}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!canWrite ? null : status === "ready" ? (
        <SealForm
          // a new form per file, so a value never carries over to another
          key={`${owner}/${repo}:${file.path}:${round}`}
          owner={owner}
          repo={repo}
          file={file}
          commit={commit}
          session={session}
          pendingKeys={pending}
          onBusyChange={onBusyChange}
          autoFocus={focusForm}
        />
      ) : (
        <p className="border-t border-border bg-muted/30 px-5 py-4 text-sm text-muted-foreground">
          {docs.length === 0
            ? `This file has no SealedSecret for the ${env} env.`
            : "A document in this file can't be sealed into, so the file can't be either. Fix it in the repository, then reload."}
        </p>
      )}
    </Panel>
  );
}

import { useCallback, useRef, useState, type ReactNode } from "react";
import { BookOpen, ExternalLink, FileWarning, Info } from "lucide-react";
import type {
  RepositoryFile,
  SealSession,
  SealedSecretDocument,
} from "@/api/types";
import { CopyButton } from "@/components/fleet/CopyButton";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { FilePath, fileStatus } from "./FileList";
import { fileHints } from "./hints";
import { KeyList } from "./KeyList";
import { keyStatuses } from "./keys";
import { SealForm, type SealFormHandle } from "./SealForm";

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

/**
 * The documents a value is sealed for: where each lives, and its scope. A
 * document values can't be sealed into says why.
 */
function Documents({
  file,
  docs,
  sealing,
}: {
  file: RepositoryFile;
  docs: SealedSecretDocument[];
  /** Whether the form above seals into them. */
  sealing: boolean;
}) {
  if (docs.length === 0) return null;
  return (
    <div className="border-t border-border">
      <h3 className="px-5 pt-4 pb-2 text-xs font-semibold tracking-wide text-muted-foreground uppercase">
        {sealing
          ? docs.length === 1
            ? "Sealed for this document"
            : `Sealed for these ${docs.length} documents`
          : docs.length === 1
            ? "1 document"
            : `${docs.length} documents`}
      </h3>
      <table className="w-full text-sm">
        <caption className="sr-only">
          SealedSecret documents in {file.path}
        </caption>
        <thead className="sr-only">
          <tr>
            <th scope="col">Namespace / name</th>
            <th scope="col">Region</th>
            <th scope="col">Scope</th>
          </tr>
        </thead>
        <tbody>
          {docs.map((d) => (
            <tr
              key={d.index}
              className="border-t border-border/60 align-top first:border-0"
            >
              <th
                scope="row"
                className="w-full py-2 pr-3 pl-5 text-left font-mono text-[13px] font-medium [overflow-wrap:anywhere]"
              >
                {d.namespace || <Dash />}
                <span className="text-muted-foreground">/</span>
                {d.name || <Dash />}
                {d.problem && (
                  <p className="mt-1 max-w-md font-sans text-xs font-normal text-warning">
                    {d.problem}
                  </p>
                )}
              </th>
              <td className="px-3 py-2 whitespace-nowrap text-muted-foreground">
                {d.region || <Dash />}
              </td>
              <td className="py-1.5 pr-5 pl-3 text-right">
                <ScopeBadge scope={d.scope} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="h-2" />
    </div>
  );
}

function Panel({
  file,
  aside,
  actions,
  children,
}: {
  file: RepositoryFile;
  aside?: ReactNode;
  actions?: ReactNode;
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
        {actions && <div className="shrink-0">{actions}</div>}
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
  const hints = fileHints(file);
  const pending = new Set(
    (session?.changes ?? [])
      .filter((c) => c.path === file.path)
      .map((c) => c.key),
  );
  const form = useRef<SealFormHandle>(null);
  const [current, setCurrent] = useState("");
  const [busy, setBusy] = useState(false);
  const busyChange = useCallback(
    (b: boolean) => {
      setBusy(b);
      onBusyChange(b);
    },
    [onBusyChange],
  );
  const sealing = canWrite && status === "ready";

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
        <>
          {hints.description && (
            <p className="text-sm text-foreground/85">{hints.description}</p>
          )}
          <p className="text-xs text-muted-foreground">
            {docs.length === 1
              ? `1 SealedSecret for the ${env} env`
              : `${docs.length} SealedSecrets for the ${env} env`}
          </p>
        </>
      }
      actions={
        hints.docs && (
          <Button asChild variant="outline" size="sm">
            <a href={hints.docs} target="_blank" rel="noopener noreferrer">
              <BookOpen className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
              Docs
              <ExternalLink
                className="ml-1.5 h-3 w-3 opacity-60"
                aria-hidden="true"
              />
              <span className="sr-only"> (opens in a new tab)</span>
            </a>
          </Button>
        )
      }
    >
      {docs.length > 0 && (
        <KeyList
          keys={keyStatuses(file, sealing ? pending : new Set())}
          docs={docs.length}
          current={sealing ? current : undefined}
          onPick={sealing ? (k) => form.current?.pick(k) : undefined}
          disabled={busy}
        />
      )}
      {!canWrite ? null : sealing ? (
        <SealForm
          // a new form per file, so a value never carries over to another
          key={`${owner}/${repo}:${file.path}:${round}`}
          ref={form}
          owner={owner}
          repo={repo}
          file={file}
          commit={commit}
          session={session}
          pendingKeys={pending}
          onBusyChange={busyChange}
          onKeyChange={setCurrent}
          autoFocus={focusForm}
        />
      ) : (
        <p className="border-t border-border bg-muted/30 px-5 py-4 text-sm text-muted-foreground">
          {docs.length === 0
            ? `This file has no SealedSecret for the ${env} env.`
            : "A document in this file can't be sealed into, so the file can't be either. Fix it in the repository, then reload."}
        </p>
      )}
      <Documents file={file} docs={docs} sealing={sealing} />
    </Panel>
  );
}

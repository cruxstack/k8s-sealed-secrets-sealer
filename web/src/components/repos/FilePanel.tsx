import { useCallback, useRef, useState, type ReactNode } from "react";
import { BookOpen, ExternalLink, Info, ShieldAlert } from "lucide-react";
import type {
  RepositoryFile,
  SealSession,
  SealedSecretDocument,
} from "@/api/types";
import { CopyButton } from "@/components/fleet/CopyButton";
import { cn, sentence } from "@/lib/utils";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { RegionTag } from "@/components/ui/region-tag";
import { CardHeading } from "@/components/ui/section-heading";
import {
  Dash,
  Table,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { FilePath, fileStatus } from "./FileList";
import { fileHints } from "./hints";
import { KeyList } from "./KeyList";
import {
  NO_PENDING,
  keyStatuses,
  pendingDocs,
  resealedDocs,
  revokedDocs,
} from "./keys";
import { ResealAll, type FileResealer } from "./ResealFile";
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

function ScopeBadge({ scope }: { scope: SealedSecretDocument["scope"] }) {
  const s = SCOPES[scope];
  // a scope that is refused needs attention; it is not a failure
  const refused = scope === "cluster-wide";
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          className="rounded-md focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          aria-label={`${s.label} scope: ${s.detail}`}
        >
          <Badge
            variant="outline"
            className={cn(
              "cursor-help",
              refused && "border-warning/60 text-warning",
            )}
          >
            {refused && <ShieldAlert className="h-3 w-3" aria-hidden="true" />}
            {s.label}
            <Info className="h-3 w-3" aria-hidden="true" />
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
 * The documents a value is sealed for: where each lives, and its scope. When
 * the seal is limited to some regions, the others say they are left out. A
 * document values can't be sealed into says why.
 */
function Documents({
  file,
  docs,
  sealing,
  regions,
}: {
  file: RepositoryFile;
  docs: SealedSecretDocument[];
  /** Whether the form above seals into them. */
  sealing: boolean;
  /** The regions the seal is limited to; null for every document. */
  regions: string[] | null;
}) {
  if (docs.length === 0) return null;
  const left = (d: SealedSecretDocument) =>
    regions !== null && !regions.includes(d.region ?? "");
  const count = docs.filter((d) => !left(d)).length;
  const note = !sealing
    ? null
    : regions !== null
      ? `Sealed for ${count} of these ${docs.length} documents`
      : docs.length === 1
        ? "Sealed for this document"
        : `Sealed for all ${docs.length}`;
  return (
    <div className="border-t border-border">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 px-4 pt-4 pb-3">
        <CardHeading as="h3" count={docs.length}>
          Documents
        </CardHeading>
        {note && (
          <p
            className={cn(
              "text-xs",
              regions !== null ? "text-primary" : "text-muted-foreground",
            )}
          >
            {note}
          </p>
        )}
      </div>
      <Table containerClassName="mx-4 mb-4">
        <caption className="sr-only">
          SealedSecret documents in {file.path}
        </caption>
        <TableHeader>
          <tr>
            <TableHead>Namespace / name</TableHead>
            <TableHead>Region</TableHead>
            <TableHead className="text-right">Scope</TableHead>
          </tr>
        </TableHeader>
        <tbody>
          {docs.map((d) => (
            <TableRow key={d.index} className="align-top">
              <th
                scope="row"
                className={cn(
                  "w-full px-4 py-2.5 text-left font-mono text-[13px] font-medium [overflow-wrap:anywhere]",
                  left(d) && "text-muted-foreground",
                )}
              >
                {d.namespace || <Dash />}
                <span className="text-muted-foreground">/</span>
                {d.name || <Dash />}
                {left(d) && (
                  <span className="ml-2 font-sans text-xs font-normal text-muted-foreground">
                    not in this seal
                  </span>
                )}
                {d.problem && (
                  <p className="mt-1 max-w-md font-sans text-xs font-normal text-warning">
                    {sentence(d.problem)}
                  </p>
                )}
              </th>
              <TableCell className="py-2.5 whitespace-nowrap">
                {d.region ? <RegionTag region={d.region} /> : <Dash />}
              </TableCell>
              <TableCell className="py-2 text-right">
                <ScopeBadge scope={d.scope} />
              </TableCell>
            </TableRow>
          ))}
        </tbody>
      </Table>
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
  const { title } = fileHints(file);
  const path = (
    <>
      <FilePath path={file.path} />
      <CopyButton value={file.path} label="file path" />
    </>
  );
  return (
    <section
      aria-label={file.path}
      className="overflow-hidden rounded-xl border bg-card shadow-xs dark:shadow-none"
    >
      {/* on a phone the actions go under the path, which needs the width */}
      <div className="flex flex-col gap-3 border-b border-border px-4 py-3 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
        <div className="min-w-0 space-y-1">
          {/* a file's title names it, with its path under it */}
          {title ? (
            <>
              <h2 className="text-[15px] leading-6 font-semibold">{title}</h2>
              <p className="flex items-center gap-1 text-[13px]">{path}</p>
            </>
          ) : (
            <h2 className="flex items-center gap-1 text-[15px] leading-6">
              {path}
            </h2>
          )}
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
  resealer,
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
  /** "Reseal all", for the env's admins; absent for everyone else. */
  resealer?: FileResealer;
}) {
  const status = fileStatus(file);
  const docs = file.documents ?? [];
  const hints = fileHints(file);
  const changes = session?.changes ?? [];
  const pending = pendingDocs(changes, file.path);
  const revoked = revokedDocs(changes, file.path);
  const resealed = resealedDocs(changes, file.path);
  const form = useRef<SealFormHandle>(null);
  const [current, setCurrent] = useState("");
  // the regions the form's seal is limited to; null for every document
  const [regions, setRegions] = useState<string[] | null>(null);
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
        <div className="p-4">
          <Alert
            variant="destructive"
            role="alert"
            heading="Could not read this file"
          >
            {sentence(file.error ?? "")} Fix it in the repository, then reload.
          </Alert>
        </div>
      </Panel>
    );
  }

  const keys = keyStatuses(
    file,
    sealing ? pending : NO_PENDING,
    sealing ? revoked : NO_PENDING,
    sealing ? resealed : NO_PENDING,
  );

  return (
    <Panel
      file={file}
      aside={
        <>
          {hints.description && (
            <p className="text-sm text-foreground">{hints.description}</p>
          )}
          <p className="text-xs text-muted-foreground">
            {docs.length === 1
              ? `1 SealedSecret for the ${env} env`
              : `${docs.length} SealedSecrets for the ${env} env`}
          </p>
        </>
      }
      actions={
        (hints.docs || resealer) && (
          <div className="flex flex-wrap items-center gap-2">
            {hints.docs && (
              <Button asChild variant="outline" size="sm">
                <a href={hints.docs} target="_blank" rel="noopener noreferrer">
                  <BookOpen className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
                  Docs
                  <ExternalLink
                    className="ml-1.5 h-3 w-3 text-muted-foreground"
                    aria-hidden="true"
                  />
                  <span className="sr-only"> (opens in a new tab)</span>
                </a>
              </Button>
            )}
            {resealer && (
              <ResealAll
                file={file}
                env={env}
                session={session}
                commit={commit}
                canWrite={canWrite}
                sealing={busy}
                resealer={resealer}
              />
            )}
          </div>
        )
      }
    >
      {/* a file nothing can be sealed into lists only the keys it holds */}
      {docs.length > 0 && (sealing || keys.length > 0) && (
        <KeyList
          keys={keys}
          docs={docs.length}
          current={sealing ? current : undefined}
          onPick={sealing ? (k, rs) => form.current?.pick(k, rs) : undefined}
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
          pending={pending}
          onBusyChange={busyChange}
          onKeyChange={setCurrent}
          onRegionsChange={setRegions}
          autoFocus={focusForm}
        />
      ) : (
        <div
          className={cn(
            "p-4",
            (keys.length > 0 || docs.length === 0) && "border-t border-border",
          )}
        >
          {docs.length === 0 ? (
            <Alert variant="info">
              This file has no SealedSecret for the {env} env.
            </Alert>
          ) : (
            <Alert
              variant="warning"
              heading="Values can't be sealed into this file"
            >
              A document below can't be sealed into, so the file can't be
              either. Fix it in the repository, then reload.
            </Alert>
          )}
        </div>
      )}
      <Documents
        file={file}
        docs={docs}
        sealing={sealing}
        regions={sealing ? regions : null}
      />
    </Panel>
  );
}

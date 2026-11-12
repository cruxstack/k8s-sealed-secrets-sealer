// Types for the control plane's /api/v1 responses.

/** The signed-in GitHub user. */
export interface AuthUser {
  id: number;
  login: string;
  name?: string;
  avatar_url?: string;
}

/** An env the user may use. */
export interface EnvAccess {
  name: string;
  /** Admins (members of one of the env's admin teams) see its fleet. */
  admin: boolean;
}

/** GET /api/v1/auth/me */
export interface MeResponse {
  user: AuthUser;
  /** The envs the user may use, in the order the deployment lists them. */
  envs: EnvAccess[];
  /** Sent back as X-CSRF-Token on every state-changing request. */
  csrf_token: string;
}

/** A sealing key, identified by the controller's fingerprint. */
export interface KeyRef {
  fingerprint: string;
  not_before: string;
  not_after: string;
}

/** The sealed-secrets controller beside an agent. */
export interface ControllerInfo {
  namespace: string;
  name: string;
  key_renew_period?: string;
  key_order_priority?: string;
  active_fingerprint: string;
}

/** One registered agent and what is known about it. */
export interface FleetAgent {
  id: string;
  cluster: string;
  region: string;
  registered_capabilities: string[] | null;
  checked_in: boolean;
  healthy: boolean;
  in_scope: boolean;
  last_checkin?: string;
  agent_version?: string;
  capabilities?: string[] | null;
  controller?: ControllerInfo;
  keys?: KeyRef[] | null;
  keys_complete: boolean;
  /** How many keys the agent reported; more than `keys` past the limit. */
  keys_reported: number;
  /** How many of them, the oldest, were left out over the key limit. */
  keys_dropped: number;
  missing_keys?: string[] | null;
  /**
   * Set while the cluster, new or rebuilt, is left out of the env key as it
   * restores the env's keys (for up to 30 minutes after it joined).
   */
  joining: boolean;
  joined_at?: string;
  issues?: string[] | null;
  /** The agent's latest count; absent when it has never reported one. */
  key_usage?: KeyUsage;
}

/**
 * An agent's count of the values its controller's SealedSecrets hold, by
 * the key that sealed them. Only agents with the `cleanup` capability count.
 */
export interface KeyUsage {
  /** When the control plane received the count (its clock). */
  counted_at: string;
  /** The namespaces counted; null for every namespace. */
  namespaces: string[] | null;
  sealed_secrets: number;
  values: number;
  /** Values no key in the cluster decrypts: the controller cannot either. */
  unmatched: number;
  /** Why the count failed; the counts are absent then. */
  error?: string;
}

/** One cluster's count of the values sealed with a key. */
export interface KeyClusterReferences {
  agent: string;
  cluster: string;
  values: number;
  sealed_secrets: number;
  counted_at: string;
}

/** The values sealed with a key, across the env's clusters. */
export interface KeyReferences {
  /** Values sealed with the key, summed over the clusters that counted. */
  values: number;
  /** SealedSecrets holding at least one of them. */
  sealed_secrets: number;
  /** One entry per in-scope cluster that counted, including those counting 0. */
  clusters: KeyClusterReferences[] | null;
  /**
   * In-scope agents whose clusters did not count: no cleanup capability,
   * never counted, a failed count, or a count older than an hour.
   */
  uncounted: string[] | null;
}

/** One of the env's sealing keys. */
export interface FleetKey extends KeyRef {
  /** The agents whose clusters report the key. */
  holders: string[] | null;
  escrow_copies: number;
  env_key: boolean;
  status: "active" | "revoked" | "deleted";
  /** Kept on a deleted key, which was revoked first. */
  revoked_by?: string;
  revoked_at?: string;
  /** On a deleted key: who deleted it and when. */
  deleted_by?: string;
  deleted_at?: string;
  /** On a deleted key: when its escrowed copies are purged. */
  purge_at?: string;
  /** Set once purge_at has passed: the key cannot be reinstated. */
  purged: boolean;
  /** Valid only from more than an hour ahead: not used until then. */
  future_dated: boolean;
  references: KeyReferences;
  /** Whether an admin may delete the key now (only a revoked key). */
  deletable: boolean;
  /** Why a revoked key cannot be deleted now, as a sentence. */
  delete_blocked?: string;
}

/** GET /api/v1/fleet */
export interface Fleet {
  env: string;
  /** The newest key every in-scope cluster holds; null when there is none. */
  env_key: KeyRef | null;
  keys_in_sync: boolean;
  /**
   * Set when there is no env key although no cluster is missing a key: every
   * key the clusters share is revoked or not valid yet, so a new key is
   * needed.
   */
  no_usable_key?: boolean;
  /** How many keys of a cluster the control plane keeps track of. */
  key_limit: number;
  /**
   * The keys clusters report, the revoked keys, and the deleted keys until
   * no cluster holds them and their escrowed copies are purged; newest
   * first.
   */
  keys: FleetKey[] | null;
  agents: FleetAgent[] | null;
}

/** POST /api/v1/keys/{fingerprint}/revoke, .../reinstate and .../delete */
export interface KeyStatus {
  fingerprint: string;
  status: "active" | "revoked" | "deleted";
  status_by?: string;
  status_at?: string;
}

/** GET /api/v1/status: whether values can be sealed in the env. */
export interface SealingStatus {
  env: string;
  sealing: "ready" | "degraded" | "unavailable";
  message: string;
  clusters: { ready: number; total: number };
  /**
   * Whether values can be resealed: there is an env key and an agent with
   * the `reseal` capability holds it. A control plane from before
   * resealing leaves it out, and cannot.
   */
  can_reseal?: boolean;
  /** Why values cannot be resealed, as a sentence. */
  reseal_blocked?: string;
}

/** Body of every API error response. */
export interface ApiErrorEnvelope {
  error: string;
}

/** A repository the signed-in user can read. */
export interface Repository {
  owner: string;
  name: string;
  full_name: string;
  private: boolean;
  default_branch: string;
  /** "write" or "read": the user's own permission on GitHub. */
  access: "write" | "read";
}

/** GET /api/v1/repos */
export interface RepositoryList {
  repositories: Repository[];
  /**
   * Set when repositories the user can read may be missing: GitHub did not
   * answer for all of them in time.
   */
  incomplete?: boolean;
}

/** A SealedSecret document for this env. */
export interface SealedSecretDocument {
  /** Position in the file, counting from 0. */
  index: number;
  name: string;
  namespace: string;
  region?: string;
  scope: "strict" | "namespace-wide" | "cluster-wide";
  /** Names in spec.encryptedData. */
  keys: string[];
  /** Why values cannot be sealed into it; absent when they can. */
  problem?: string;
  /** Optional hints from the document's annotations, for people. */
  /** A short name for the secret, shown before its path. */
  title?: string;
  /** What the secret is for. */
  description?: string;
  /** The keys the document should hold. */
  expected_keys?: string[];
  /** An http(s) link to the secret's docs. */
  docs?: string;
}

/** A file holding SealedSecret documents for this env. */
export interface RepositoryFile {
  path: string;
  blob: string;
  documents: SealedSecretDocument[] | null;
  /** Why the file could not be read. */
  error?: string;
}

/** GET /api/v1/repos/{owner}/{repo}/files */
export interface FileListing {
  repository: Repository;
  branch: string;
  commit: string;
  files: RepositoryFile[];
  truncated: boolean;
  /** Globs that select the files searched. */
  file_globs: string[];
}

/** A SealedSecret document a value is sealed for. */
export interface SealTarget {
  /** The document's position in the file; absent for older changes. */
  index?: number;
  namespace: string;
  name: string;
  scope: "strict" | "namespace-wide";
  region?: string;
}

/** An agent, as users see it. */
export interface AgentRef {
  id: string;
  cluster?: string;
  region?: string;
}

/**
 * A value sealed for the documents of a file, waiting to be committed.
 * Ciphertexts are never sent to the browser.
 */
export interface PendingChange {
  id: string;
  path: string;
  key: string;
  /** The regions the value was sealed for; absent for every document. */
  regions?: string[];
  /**
   * The documents it sets. A newer change of the same key takes over the
   * documents both name.
   */
  targets: SealTarget[];
  sealed_at: string;
  sealed_by: AgentRef;
  fingerprint: string;
  /**
   * Set when the key it was sealed with has since been revoked: it must be
   * sealed again, or removed, before a pull request.
   */
  key_revoked?: boolean;
  /**
   * `reseal`: the file's own values, moved onto the env key by "Reseal
   * all"; absent on changes stored before resealing, which are seals.
   */
  kind?: "seal" | "reseal";
  /** On a reseal change: the keys its values came off. */
  resealed_from?: string[];
}

/** The user's pending changes to one repository, based on one commit. */
export interface SealSession {
  id: string;
  repository: string;
  owner: string;
  repo: string;
  branch: string;
  commit: string;
  created_at: string;
  /** When the session ends unless it is used again. */
  expires_at: string;
  /** The latest the session lasts, however much it is used. */
  ends_at: string;
  pending_changes: number;
  /** Present on a single session, absent in listings. */
  changes?: PendingChange[];
}

/** GET /api/v1/repos/{owner}/{repo}/session */
export interface SessionResponse {
  session: SealSession | null;
}

/** GET /api/v1/sessions */
export interface SessionList {
  sessions: SealSession[];
}

/** POST /api/v1/repos/{owner}/{repo}/session/{id}/pull-request */
export interface PullRequest {
  number: number;
  /** The pull request on GitHub. */
  url: string;
  branch: string;
  title: string;
  files: number;
  changes: number;
}

/**
 * Where a seal stands. `superseded`: it sealed, but a newer seal of the key
 * replaced its value in the session.
 */
export type SealStatus =
  "queued" | "sealing" | "sealed" | "superseded" | "failed" | "expired";

/** A seal's progress. */
export interface Seal {
  id: string;
  status: SealStatus;
  path: string;
  key: string;
  /** The regions the seal was limited to; absent for every document. */
  regions?: string[];
  targets: SealTarget[];
  agent: AgentRef;
  fingerprint: string;
  created_at: string;
  /** The pending change the value went into, once sealed. */
  change_id?: string;
  error?: string;
}

/** Counts of values by what resealing did with them. */
export interface ResealCounts {
  /** Moved onto the env key. */
  resealed: number;
  /** Already on the env key: unchanged. */
  current: number;
  /** No key the agent holds opened them, or the agent did not answer. */
  failed: number;
}

/** Where a run of a schedule stands. */
export type ResealRunStatus =
  "queued" | "running" | "succeeded" | "partial" | "failed" | "cancelled";

/**
 * A schedule that reseals every value in its repositories, and in every
 * repository of its orgs, every `interval_days`.
 * GET /api/v1/reseal/schedules
 */
export interface ResealSchedule {
  id: string;
  name: string;
  /** "owner/name" */
  repos: string[];
  orgs: string[];
  interval_days: number;
  enabled: boolean;
  /** Null while it is paused. */
  next_run_at: string | null;
  created_by: string;
  created_at: string;
  updated_by?: string;
  updated_at?: string;
  /** Its latest run, if any. */
  last_run?: ResealRunSummary;
  /** Set while a run of it is queued or running. */
  active_run_id?: string;
}

/** POST /api/v1/reseal/schedules, and any part of it for PATCH. */
export interface ResealScheduleInput {
  name: string;
  repos: string[];
  orgs: string[];
  interval_days: number;
  enabled: boolean;
}

/** One run of a schedule. GET /api/v1/reseal/runs, newest first. */
export interface ResealRunSummary {
  id: string;
  schedule_id: string;
  schedule_name: string;
  /** `manual`: Run now, by `requested_by`. */
  trigger: "schedule" | "manual";
  requested_by: string;
  status: ResealRunStatus;
  started_at: string;
  finished_at?: string;
  /** `hidden`: those in repositories the viewer cannot read. */
  repos: { total: number; done: number; hidden: number };
  values: ResealCounts;
  pull_requests: number;
  error?: string;
}

/** GET /api/v1/reseal/runs/{id} */
export interface ResealRun extends ResealRunSummary {
  /** Only the repositories the viewer can read. */
  repositories: ResealRunRepo[];
}

/** What a run did in one repository. */
export interface ResealRunRepo {
  repo: string;
  status:
    | "pending"
    | "resealing"
    | "opening"
    | "opened"
    | "unchanged"
    | "skipped"
    | "failed";
  files: number;
  values: ResealCounts;
  pull_request?: { number: number; url: string };
  /** Why it was skipped or failed, as a sentence. */
  reason?: string;
  /** Values that could not be resealed, at most 50. */
  failures?: ResealFailure[];
}

/** A value that could not be resealed. */
export interface ResealFailure {
  path: string;
  key: string;
  /** The document's position in the file, counting from 0. */
  document: number;
  region?: string;
  error: string;
}

export type ResealPullRequestState = "open" | "merged" | "closed";

/**
 * A pull request with resealed values: one a run opened, or one opened
 * from a session with reseal changes.
 */
export interface ResealPullRequest {
  repo: string;
  number: number;
  url: string;
  title: string;
  branch: string;
  state: ResealPullRequestState;
  source: "schedule" | "session";
  schedule_id?: string;
  schedule_name?: string;
  run_id?: string;
  requested_by: string;
  opened_at: string;
  merged_at?: string;
  closed_at?: string;
  /** When its state was last read from GitHub. */
  checked_at: string;
  values: number;
  files: number;
  /** Fingerprints of the keys it moves values off. */
  from_keys: string[];
}

/** GET /api/v1/reseal/pull-requests?state= */
export interface ResealPullRequestList {
  pull_requests: ResealPullRequest[];
  /** How many more are in repositories the viewer cannot read. */
  hidden: number;
}

/** Where resealing one file in a session stands. */
export type FileResealStatus =
  "queued" | "resealing" | "done" | "failed" | "expired";

/**
 * "Reseal all" on one file, in a session: its values on older keys move
 * onto the env key as pending changes.
 * POST and GET /api/v1/repos/{owner}/{repo}/session/{id}/reseals
 */
export interface FileReseal {
  id: string;
  path: string;
  status: FileResealStatus;
  values: ResealCounts & {
    /** The values of this env's documents in the file. */
    total: number;
    /** Left out: a pending change in the session already sets them. */
    pending: number;
  };
  failures?: Omit<ResealFailure, "path">[];
  /** The pending changes it made. */
  change_ids?: string[];
  agent?: AgentRef;
  created_at: string;
  error?: string;
}

/** What the GitHub App setup page shows, while the App is not set up. */
export interface SetupStatus {
  org: string;
  github_url: string;
  public_url: string;
  /** The name the App is offered under; it can be changed on GitHub. */
  app_name: string;
  permissions: { name: string; access: "read" | "write" }[];
}

/** The form the setup page posts to GitHub to create the App. */
export interface SetupForm {
  action: string;
  manifest: string;
}

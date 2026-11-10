// Types for the control plane's /api/v1 responses.

/** The signed-in GitHub user. */
export interface AuthUser {
  id: number;
  login: string;
  name?: string;
  avatar_url?: string;
  /** Admins (members of an admin team) may see the fleet. */
  admin?: boolean;
}

/** GET /api/v1/auth/me */
export interface MeResponse {
  user: AuthUser;
  /** Sent back as X-CSRF-Token on every state-changing request. */
  csrf_token: string;
  env: string;
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
  missing_keys?: string[] | null;
  issues?: string[] | null;
}

/** GET /api/v1/fleet */
export interface Fleet {
  env: string;
  /** The newest key every in-scope cluster holds; null when there is none. */
  env_key: KeyRef | null;
  keys_in_sync: boolean;
  agents: FleetAgent[] | null;
}

/** GET /api/v1/status: whether values can be sealed in the env. */
export interface SealingStatus {
  env: string;
  sealing: "ready" | "degraded" | "unavailable";
  message: string;
  clusters: { ready: number; total: number };
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
 * A value sealed for every document of a file, waiting to be committed.
 * Ciphertexts are never sent to the browser.
 */
export interface PendingChange {
  id: string;
  path: string;
  key: string;
  targets: SealTarget[];
  sealed_at: string;
  sealed_by: AgentRef;
  fingerprint: string;
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

export type SealStatus = "queued" | "sealing" | "sealed" | "failed" | "expired";

/** A seal's progress. */
export interface Seal {
  id: string;
  status: SealStatus;
  path: string;
  key: string;
  targets: SealTarget[];
  agent: AgentRef;
  fingerprint: string;
  created_at: string;
  /** The pending change the value went into, once sealed. */
  change_id?: string;
  error?: string;
}

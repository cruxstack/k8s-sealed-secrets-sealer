import axios, { AxiosHeaders, type AxiosError } from "axios";

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS", "TRACE"]);

// ---------------------------------------------------------------------------
// CSRF
// ---------------------------------------------------------------------------

// The session cookie is HttpOnly, so the CSRF token comes from /auth/me and
// is kept in memory for the page's lifetime.
let csrfToken: string | null = null;

export function setCsrfToken(token: string | null) {
  csrfToken = token;
}

// ---------------------------------------------------------------------------
// Env
// ---------------------------------------------------------------------------

// The env the page is in, from its path. Every API call but signing in is
// about one env, under /api/v1/envs/{env}/.
let apiEnv: string | null = null;

export function setApiEnv(env: string | null) {
  apiEnv = env;
}

export function currentApiEnv(): string | null {
  return apiEnv;
}

// ---------------------------------------------------------------------------
// Navigation (indirect so tests can observe it; jsdom cannot navigate)
// ---------------------------------------------------------------------------

export const navigation = {
  assign(url: string) {
    window.location.assign(url);
  },
};

/** The login page URL that brings the user back to where they are now. */
export function loginRedirectURL(): string {
  const { pathname, search } = window.location;
  const current = `${pathname}${search}`;
  if (pathname === "/login" || current === "/") return "/login";
  return `/login?return_to=${encodeURIComponent(current)}`;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

const GENERIC_ERROR_MESSAGE = "An unexpected error occurred. Please try again.";

/**
 * Sanitized API error. Carries only a human-readable message and the HTTP
 * status: no axios config, request or response objects, so request bodies
 * (which will contain plaintext secret values once sealing exists) are never
 * retained by error state, caches or console logging.
 */
export class ApiError extends Error {
  readonly status: number | undefined;
  /** Seconds to wait before asking again, from a 429's or 503's Retry-After. */
  readonly retryAfter: number | undefined;

  constructor(message: string, status?: number, retryAfter?: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.retryAfter = retryAfter;
  }
}

/** A response header, whatever its case and however axios holds it. */
function headerValue(headers: unknown, name: string): unknown {
  if (headers instanceof AxiosHeaders) return headers.get(name);
  if (!isRecord(headers)) return undefined;
  const key = Object.keys(headers).find(
    (k) => k.toLowerCase() === name.toLowerCase(),
  );
  return key === undefined ? undefined : headers[key];
}

/** Retry-After in seconds; only the delay form, which the API sends. */
function retryAfterSeconds(value: unknown): number | undefined {
  const n = typeof value === "string" ? Number(value) : NaN;
  return Number.isFinite(n) && n >= 0 ? n : undefined;
}

/** Messages for statuses whose bodies say nothing more useful. */
const STATUS_MESSAGES: Record<number, string> = {
  400: "The request was invalid",
  401: "Your session has expired — please sign in again",
  403: "You don't have permission to perform this action",
  404: "The requested resource was not found",
  409: "A conflict occurred — the resource may have been modified",
  413: "The request is too large",
  415: "The request had an unsupported format",
  422: "Invalid data submitted",
  429: "Too many requests — please wait and try again",
  500: "The server encountered an error — please try again",
  502: "The server could not complete the request — please try again",
  503: "The service is temporarily unavailable — please try again",
  504: "The operation timed out — please try again",
};

// Statuses whose `error` text is a bare status word; the status message reads
// better than "unauthorized" or "internal error". A 503 says what is
// unavailable and when to try again, so its text is shown.
const GENERIC_BODY_STATUSES = new Set([401, 404, 500, 502, 504]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The message in an API error body (`{"error": "..."}`), if there is one. */
function messageFromEnvelope(status: number, data: unknown): string | null {
  if (!isRecord(data) || GENERIC_BODY_STATUSES.has(status)) return null;
  const { error } = data;
  if (typeof error !== "string" || error.trim() === "") return null;
  return error;
}

/**
 * Convert any thrown value into a sanitized {@link ApiError}. The returned
 * error never references the original error object.
 */
export function toApiError(error: unknown): ApiError {
  if (error instanceof ApiError) {
    return new ApiError(error.message, error.status, error.retryAfter);
  }

  if (axios.isAxiosError(error)) {
    const response = error.response;
    if (!response) {
      if (axios.isCancel(error))
        return new ApiError("The request was cancelled");
      if (error.code === "ECONNABORTED" || error.code === "ETIMEDOUT") {
        return new ApiError("The request timed out — please try again");
      }
      return new ApiError(
        "Unable to reach the server — check your connection and try again",
      );
    }

    const { status } = response;
    const message =
      messageFromEnvelope(status, response.data) ??
      STATUS_MESSAGES[status] ??
      GENERIC_ERROR_MESSAGE;
    return new ApiError(
      message,
      status,
      retryAfterSeconds(headerValue(response.headers, "Retry-After")),
    );
  }

  return new ApiError(GENERIC_ERROR_MESSAGE);
}

/** Extract a human-readable error message from any thrown value. */
export function extractApiError(error: unknown): string {
  return toApiError(error).message;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// X-Requested-With tells the control plane a request comes from this page's
// scripts, not a navigation another site started: calls that cost GitHub
// requests refuse cross-site requests, so another site cannot spend the
// user's rate limits.
const apiClient = axios.create({
  baseURL: "/api/v1",
  headers: {
    "Content-Type": "application/json",
    "X-Requested-With": "XMLHttpRequest",
  },
  withCredentials: true,
});

apiClient.interceptors.request.use((config) => {
  if (apiEnv && config.url && !config.url.startsWith("/auth/")) {
    config.url = `/envs/${encodeURIComponent(apiEnv)}${config.url}`;
  }
  const method = (config.method ?? "GET").toUpperCase();
  if (!SAFE_METHODS.has(method) && csrfToken) {
    config.headers.set("X-CSRF-Token", csrfToken);
  }
  return config;
});

// A 401 means the session ended: go to the login page, which brings the user
// back here afterwards. /auth/me answers 401 for every signed-out visitor, so
// it never redirects (the route guards handle it), and nothing redirects from
// the login page itself, so a stale session cannot loop. The AxiosError is
// replaced with a sanitized ApiError so request bodies never leak into error
// state.
apiClient.interceptors.response.use(undefined, (error: AxiosError) => {
  if (
    error.response?.status === 401 &&
    !error.config?.url?.includes("/auth/me") &&
    window.location.pathname !== "/login"
  ) {
    navigation.assign(loginRedirectURL());
  }
  return Promise.reject(toApiError(error));
});

export default apiClient;

import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Shorten a key fingerprint (`SHA256:<base64>`) for display, keeping the
 * algorithm prefix and the first characters of the digest.
 */
export function shortFingerprint(fingerprint: string, digits = 12): string {
  const [algorithm, digest] = fingerprint.includes(":")
    ? [
        fingerprint.slice(0, fingerprint.indexOf(":") + 1),
        fingerprint.slice(fingerprint.indexOf(":") + 1),
      ]
    : ["", fingerprint];
  if (digest.length <= digits) return fingerprint;
  return `${algorithm}${digest.slice(0, digits)}…`;
}

/** Format how long ago a timestamp was, e.g. "12s ago" or "3h ago". */
export function timeAgo(iso: string, now: Date = new Date()): string {
  const then = new Date(iso);
  if (Number.isNaN(then.getTime())) return "unknown";
  const seconds = Math.max(
    0,
    Math.round((now.getTime() - then.getTime()) / 1000),
  );
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

/** Format a timestamp as a short, locale-aware date and time. */
export function formatDateTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "unknown";
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/**
 * Return `path` if it is a same-origin path (`/...`), otherwise `/`. Used for
 * `return_to`, which comes from the query string and so is attacker-controlled.
 */
export function safeReturnPath(path: unknown): string {
  if (typeof path !== "string" || !path.startsWith("/")) return "/";
  // "//host" and "/\host" are protocol-relative URLs in browsers
  if (path.startsWith("//") || path.startsWith("/\\")) return "/";
  if (path.startsWith("/login")) return "/";
  return path;
}

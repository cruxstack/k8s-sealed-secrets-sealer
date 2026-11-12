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

/**
 * How far a timestamp is from now, in the past ("12s ago", "3h ago") or the
 * future ("in 40m", "in 2d"); "just now" within a few seconds. Show it with
 * the absolute time (formatDateTime) in the element's title.
 */
export function relativeTime(iso: string, now: Date = new Date()): string {
  const then = new Date(iso);
  if (Number.isNaN(then.getTime())) return "unknown";
  const diff = Math.round((then.getTime() - now.getTime()) / 1000);
  const seconds = Math.abs(diff);
  if (seconds < 5) return "just now";
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const span =
    seconds < 60
      ? `${seconds}s`
      : minutes < 60
        ? `${minutes}m`
        : hours < 48
          ? `${hours}h`
          : `${Math.floor(hours / 24)}d`;
  return diff < 0 ? `${span} ago` : `in ${span}`;
}

/**
 * How long ago something happened, e.g. "12s ago" or "3h ago". A time a
 * little ahead of this browser's clock counts as now.
 */
export function timeAgo(iso: string, now: Date = new Date()): string {
  const then = new Date(iso);
  if (Number.isNaN(then.getTime())) return "unknown";
  return relativeTime(
    new Date(Math.min(then.getTime(), now.getTime())).toISOString(),
    now,
  );
}

/** Format a timestamp as a short, locale-aware date and time. */
export function formatDateTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "unknown";
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

/**
 * A past time as a hover says it, at a glance and exactly: "52s ago, Nov
 * 11, 2026, 8:10 PM".
 */
export function timeAgoAt(iso: string, now: Date = new Date()): string {
  return `${timeAgo(iso, now)}, ${formatDateTime(iso)}`;
}

/**
 * Text from the server as a sentence: a capital first letter and a full
 * stop. A first word that is an identifier (a path, `metadata.name`) keeps
 * its case.
 */
export function sentence(text: string): string {
  let out = text.trim();
  if (out === "") return out;
  if (/^[a-z][a-z-]*(?=[\s,;:]|$)/.test(out)) {
    out = out.charAt(0).toUpperCase() + out.slice(1);
  }
  return /[.!?…]$/.test(out) ? out : `${out}.`;
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

/** Returns `url` if it is an http(s) URL, else null; for links from the API. */
export function safeHttpUrl(url: string | undefined): string | null {
  if (!url) return null;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" || parsed.protocol === "http:"
      ? parsed.toString()
      : null;
  } catch {
    return null;
  }
}

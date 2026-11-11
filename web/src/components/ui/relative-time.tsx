import { formatDateTime, relativeTime, timeAgo } from "@/lib/utils";

/**
 * A time as people read it at a glance ("3m ago", "in 2d", "just now"),
 * with the absolute date and time in its title. `describe` words the title
 * around the absolute time ("Last check-in …").
 */
export function RelativeTime({
  iso,
  now,
  past = false,
  describe,
  className,
}: {
  iso: string;
  now?: Date;
  /** It already happened: a time just ahead of this clock reads "just now". */
  past?: boolean;
  describe?: (absolute: string) => string;
  className?: string;
}) {
  const absolute = formatDateTime(iso);
  return (
    <time
      dateTime={iso}
      title={describe ? describe(absolute) : absolute}
      className={className}
    >
      {past ? timeAgo(iso, now) : relativeTime(iso, now)}
    </time>
  );
}

/**
 * Removes every key of this origin's local storage that starts with the
 * prefix, whoever it was for. Storage can be missing or refused (a private
 * window, blocked site data); there is nothing to remove then.
 */
export function removeByPrefix(prefix: string): void {
  try {
    const keys: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k?.startsWith(prefix)) keys.push(k);
    }
    for (const k of keys) localStorage.removeItem(k);
  } catch {
    // nothing to remove when storage can't be used
  }
}

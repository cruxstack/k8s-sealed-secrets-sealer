import { useEffect, useRef } from "react";

/** Whether the platform's command key is ⌘ (Apple) rather than Ctrl. */
export function isApple(): boolean {
  if (typeof navigator === "undefined") return false;
  return /Mac|iPhone|iPad|iPod/.test(navigator.platform || navigator.userAgent);
}

/** The label of the platform's command key: "⌘" or "Ctrl". */
export function modKey(): string {
  return isApple() ? "⌘" : "Ctrl";
}

/** Whether a key event comes from somewhere the user types. */
export function isTyping(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return (
    target.isContentEditable ||
    target instanceof HTMLInputElement ||
    target instanceof HTMLTextAreaElement ||
    target instanceof HTMLSelectElement
  );
}

/**
 * Calls handler on a global keydown that matches: `key` is the key, and
 * `mod` asks for ⌘ or Ctrl. Shortcuts without a modifier never fire while
 * the user is typing.
 */
export function useShortcut(
  key: string,
  handler: (e: KeyboardEvent) => void,
  { mod = false, enabled = true }: { mod?: boolean; enabled?: boolean } = {},
) {
  const latest = useRef(handler);
  useEffect(() => {
    latest.current = handler;
  });
  useEffect(() => {
    if (!enabled) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key.toLowerCase() !== key.toLowerCase() || e.altKey) return;
      const withMod = e.metaKey || e.ctrlKey;
      if (mod !== withMod) return;
      if (!mod && isTyping(e.target)) return;
      e.preventDefault();
      latest.current(e);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [key, mod, enabled]);
}

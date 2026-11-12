import { useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { cn } from "@/lib/utils";
import { Tooltip, TooltipContent, TooltipTrigger } from "./tooltip";

/** Whether any part of an element is cut short by `truncate`. */
function isCut(el: HTMLElement): boolean {
  const parts = [el, ...el.querySelectorAll<HTMLElement>(".truncate")];
  return parts.some(
    (e) => e.classList.contains("truncate") && e.scrollWidth > e.clientWidth,
  );
}

/**
 * Something kept to one line, such as a header's path or a file's
 * description: cut with an ellipsis (`truncate`) where it does not fit,
 * with the whole of it in a tooltip on hover, keyboard focus and a tap.
 * Only while it is cut: then it is focusable too, so the whole reaches a
 * keyboard; when it fits, it is plain text. A screen reader reads the
 * whole from the content already, so the tooltip is for the eye.
 */
export function OneLine({
  full,
  children,
  className,
  tooltipClassName,
}: {
  /** The whole of it, for the tooltip. */
  full: ReactNode;
  /** It, on one line, in elements that `truncate`. */
  children: ReactNode;
  className?: string;
  tooltipClassName?: string;
}) {
  const ref = useRef<HTMLSpanElement>(null);
  const [cut, setCut] = useState(false);
  const [open, setOpen] = useState(false);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const check = () => setCut(isCut(el));
    check();
    // the space it has changes with the window and what sits beside it,
    // and what it holds with the file shown
    const resized = new ResizeObserver(check);
    resized.observe(el);
    const changed = new MutationObserver(check);
    changed.observe(el, {
      subtree: true,
      childList: true,
      characterData: true,
    });
    return () => {
      resized.disconnect();
      changed.disconnect();
    };
  }, []);
  return (
    <Tooltip open={cut && open} onOpenChange={setOpen}>
      <TooltipTrigger asChild>
        <span
          ref={ref}
          tabIndex={cut ? 0 : undefined}
          // the content says it all already; not again as a description
          aria-describedby={undefined}
          className={cn(
            "block min-w-0 rounded-sm focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none",
            className,
          )}
          onClick={(e) => {
            if (!cut) return;
            // the tooltip would close on a click; a tap is how a touch
            // screen asks for the whole, so keep it open
            e.preventDefault();
            setOpen(true);
          }}
        >
          {children}
        </span>
      </TooltipTrigger>
      <TooltipContent
        side="bottom"
        align="start"
        aria-hidden="true"
        className={cn(
          "pointer-events-none max-w-[min(40rem,calc(100vw-2rem))] text-left whitespace-normal",
          tooltipClassName,
        )}
      >
        {full}
      </TooltipContent>
    </Tooltip>
  );
}

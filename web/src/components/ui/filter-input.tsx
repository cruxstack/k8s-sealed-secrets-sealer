import type { InputHTMLAttributes, RefObject } from "react";
import { Search, X } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Kbd } from "@/components/ui/kbd";
import { cn } from "@/lib/utils";

/**
 * A list's filter: a search field that shows its `/` shortcut while empty
 * and a clear button once it has text. The browser's own clear button is
 * hidden, so the two never overlap.
 */
export function FilterInput({
  inputRef,
  value,
  onValueChange,
  className,
  ...props
}: Omit<InputHTMLAttributes<HTMLInputElement>, "value" | "type"> & {
  inputRef: RefObject<HTMLInputElement | null>;
  value: string;
  onValueChange: (value: string) => void;
}) {
  return (
    <div className={cn("relative", className)}>
      <Search
        className="pointer-events-none absolute top-1/2 left-2.5 h-4 w-4 -translate-y-1/2 text-muted-foreground"
        aria-hidden="true"
      />
      <Input
        ref={inputRef}
        type="search"
        value={value}
        onChange={(e) => onValueChange(e.target.value)}
        aria-keyshortcuts="/"
        className="h-9 pr-9 pl-8 [&::-webkit-search-cancel-button]:hidden"
        {...props}
      />
      {value ? (
        <button
          type="button"
          onClick={() => {
            onValueChange("");
            inputRef.current?.focus();
          }}
          aria-label="Clear filter"
          title="Clear filter"
          className="absolute top-1/2 right-1.5 inline-flex h-6 w-6 -translate-y-1/2 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-muted hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
        >
          <X className="h-3.5 w-3.5" aria-hidden="true" />
        </button>
      ) : (
        <Kbd
          className="pointer-events-none absolute top-1/2 right-2.5 -translate-y-1/2"
          aria-hidden="true"
        >
          /
        </Kbd>
      )}
    </div>
  );
}

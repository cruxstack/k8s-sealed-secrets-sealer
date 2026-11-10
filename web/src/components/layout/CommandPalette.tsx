import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import {
  FolderGit2,
  KeyRound,
  Layers,
  LogOut,
  Moon,
  Server,
  Sun,
  type LucideIcon,
} from "lucide-react";
import { useLogout } from "@/api/queries/auth";
import { reposQueryOptions } from "@/api/queries/repos";
import { sessionsQueryOptions } from "@/api/queries/sessions";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import { Kbd } from "@/components/ui/kbd";
import { useAuth } from "@/lib/auth";
import { useEnv } from "@/lib/env";
import { useShortcut } from "@/lib/shortcuts";
import { useTheme } from "@/lib/theme-provider";

const PaletteContext = createContext<{ open: () => void }>({
  open: () => {},
});

/** Opens the command palette, e.g. from the header's search button. */
export function useCommandPalette() {
  return useContext(PaletteContext);
}

/**
 * The command palette: ⌘K (Ctrl+K) anywhere in the signed-in app jumps to a
 * repository or a page, or runs an action.
 */
export function CommandPaletteProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const value = useMemo(() => ({ open: () => setOpen(true) }), []);
  useShortcut("k", () => setOpen((o) => !o), { mod: true });
  return (
    <PaletteContext.Provider value={value}>
      {children}
      <DialogPrimitive.Root open={open} onOpenChange={setOpen}>
        <DialogPrimitive.Portal>
          <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/40 backdrop-blur-[1px]" />
          <DialogPrimitive.Content
            className="fixed top-[12vh] left-1/2 z-50 w-[calc(100%-2rem)] max-w-xl -translate-x-1/2 overflow-hidden rounded-xl border bg-popover shadow-2xl"
            aria-describedby={undefined}
          >
            <DialogPrimitive.Title className="sr-only">
              Search repositories and pages
            </DialogPrimitive.Title>
            {open && <Palette onDone={() => setOpen(false)} />}
          </DialogPrimitive.Content>
        </DialogPrimitive.Portal>
      </DialogPrimitive.Root>
    </PaletteContext.Provider>
  );
}

function Item({
  icon: Icon,
  label,
  hint,
  value,
  keywords,
  onSelect,
  mono = false,
}: {
  icon: LucideIcon;
  label: string;
  hint?: ReactNode;
  value: string;
  keywords?: string[];
  onSelect: () => void;
  mono?: boolean;
}) {
  return (
    <CommandItem value={value} keywords={keywords} onSelect={onSelect}>
      <Icon className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
      <span className={mono ? "truncate font-mono text-[13px]" : "truncate"}>
        {label}
      </span>
      {hint && (
        <span className="ml-auto flex shrink-0 items-center gap-2 text-xs text-muted-foreground">
          {hint}
        </span>
      )}
    </CommandItem>
  );
}

function Palette({ onDone }: { onDone: () => void }) {
  const navigate = useNavigate();
  const { envs } = useAuth();
  const env = useEnv();
  const { theme, setTheme } = useTheme();
  const logout = useLogout();
  // repositories are listed for the env the page is in
  const repos = useQuery({
    ...reposQueryOptions,
    enabled: env !== null,
    select: (list) => list.repositories,
  });
  const sessions = useQuery({ ...sessionsQueryOptions, enabled: env !== null });
  const pending = new Map(
    (sessions.data ?? []).map((s) => [
      s.repository.toLowerCase(),
      s.pending_changes,
    ]),
  );

  const run = useCallback(
    (action: () => void) => {
      onDone();
      action();
    },
    [onDone],
  );
  const dark =
    theme === "dark" ||
    (theme === "system" &&
      window.matchMedia("(prefers-color-scheme: dark)").matches);

  return (
    <Command loop>
      <CommandInput placeholder="Search repositories and pages…" />
      <CommandList>
        <CommandEmpty>
          {repos.isPending ? "Loading repositories…" : "Nothing matches."}
        </CommandEmpty>
        {repos.data && repos.data.length > 0 && (
          <CommandGroup heading="Repositories">
            {repos.data.map((r) => {
              const count = pending.get(r.full_name.toLowerCase());
              return (
                <Item
                  key={r.full_name}
                  icon={FolderGit2}
                  label={r.full_name}
                  mono
                  value={`repo:${r.full_name}`}
                  keywords={[r.full_name, r.name]}
                  hint={
                    <>
                      {count ? (
                        <span className="rounded-md bg-primary/10 px-1.5 py-0.5 font-medium text-primary">
                          {count} pending
                        </span>
                      ) : null}
                      {r.access === "read" && <span>read only</span>}
                    </>
                  }
                  onSelect={() =>
                    run(
                      () =>
                        void navigate({
                          to: "/$env/secrets/$owner/$repo",
                          params: {
                            env: env?.name ?? "",
                            owner: r.owner,
                            repo: r.name,
                          },
                        }),
                    )
                  }
                />
              );
            })}
          </CommandGroup>
        )}
        {env && (
          <CommandGroup heading="Go to">
            <Item
              icon={KeyRound}
              label="Secrets"
              value="page:secrets"
              keywords={["secrets", "repositories", "repos", "home"]}
              onSelect={() =>
                run(
                  () =>
                    void navigate({
                      to: "/$env/secrets",
                      params: { env: env.name },
                    }),
                )
              }
            />
            {env.admin && (
              <Item
                icon={Server}
                label="Fleet"
                hint="admin"
                value="page:fleet"
                keywords={["fleet", "agents", "clusters", "keys", "admin"]}
                onSelect={() =>
                  run(
                    () =>
                      void navigate({
                        to: "/$env/fleet",
                        params: { env: env.name },
                      }),
                  )
                }
              />
            )}
          </CommandGroup>
        )}
        {envs.length > 1 && (
          <CommandGroup heading="Environments">
            {envs
              .filter((e) => e.name !== env?.name)
              .map((e) => (
                <Item
                  key={e.name}
                  icon={Layers}
                  label={`Switch to ${e.name}`}
                  value={`env:${e.name}`}
                  keywords={["env", "environment", "switch", e.name]}
                  onSelect={() =>
                    run(
                      () =>
                        void navigate({
                          to: "/$env/secrets",
                          params: { env: e.name },
                        }),
                    )
                  }
                />
              ))}
          </CommandGroup>
        )}
        <CommandGroup heading="Preferences">
          <Item
            icon={dark ? Sun : Moon}
            label={
              dark ? "Switch to the light theme" : "Switch to the dark theme"
            }
            value="action:theme"
            keywords={["theme", "dark", "light", "mode"]}
            onSelect={() => run(() => setTheme(dark ? "light" : "dark"))}
          />
          <Item
            icon={LogOut}
            label="Sign out"
            value="action:sign-out"
            keywords={["sign out", "log out", "logout"]}
            onSelect={() => run(() => logout.mutate())}
          />
        </CommandGroup>
      </CommandList>
      <div className="flex items-center gap-4 border-t border-border px-4 py-2 text-xs text-muted-foreground">
        <span className="flex items-center gap-1">
          <Kbd>↑</Kbd>
          <Kbd>↓</Kbd> to move
        </span>
        <span className="flex items-center gap-1">
          <Kbd>↵</Kbd> to open
        </span>
        <span className="flex items-center gap-1">
          <Kbd>esc</Kbd> to close
        </span>
      </div>
    </Command>
  );
}

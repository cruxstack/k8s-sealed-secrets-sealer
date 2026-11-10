import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import {
  Check,
  ChevronsUpDown,
  FileLock,
  LogOut,
  Search,
  Server,
} from "lucide-react";
import { ThemeToggle } from "./ThemeToggle";
import { useCommandPalette } from "./CommandPalette";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Kbd } from "@/components/ui/kbd";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import type { EnvAccess } from "@/api/types";
import { useAuth } from "@/lib/auth";
import { useEnv } from "@/lib/env";
import { modKey } from "@/lib/shortcuts";
import { cn } from "@/lib/utils";
import { useLogout } from "@/api/queries/auth";
import { statusQueryOptions } from "@/api/queries/status";

function NavLink({ env, children }: { env: string; children: string }) {
  return (
    <Link
      to="/$env/secrets"
      params={{ env }}
      className="rounded-md px-3 py-1.5 text-sm font-medium transition-colors hover:bg-muted hover:text-foreground"
      inactiveProps={{ className: "text-muted-foreground" }}
      activeProps={{
        className: "bg-muted text-foreground",
        "aria-current": "page",
      }}
    >
      {children}
    </Link>
  );
}

/** Opens the command palette; shows its shortcut. */
function SearchButton() {
  const palette = useCommandPalette();
  return (
    <Button
      variant="outline"
      size="sm"
      onClick={palette.open}
      aria-label="Search repositories and pages"
      aria-keyshortcuts="Meta+K Control+K"
      className="h-9 gap-2 px-2.5 text-muted-foreground sm:w-64 sm:justify-start"
    >
      <Search className="h-4 w-4" aria-hidden="true" />
      <span className="hidden sm:inline">Search repositories…</span>
      <span className="ml-auto hidden items-center gap-0.5 sm:flex">
        <Kbd>{modKey()}</Kbd>
        <Kbd>K</Kbd>
      </span>
    </Button>
  );
}

const SEALING = {
  ready: { dot: "bg-success", label: "sealing works" },
  degraded: {
    dot: "bg-warning",
    label: "sealing works, some clusters are not ready",
  },
  unavailable: { dot: "bg-destructive", label: "sealing is unavailable" },
} as const;

/** The env's name with a dot that says whether sealing works. */
function EnvDot({ dot }: { dot: string | undefined }) {
  return (
    <span
      className={cn(
        "h-1.5 w-1.5 rounded-full",
        dot ?? "bg-muted-foreground/40",
      )}
      aria-hidden="true"
    />
  );
}

/**
 * The env badge, with a dot that says whether sealing works. Admins can open
 * the fleet from it; everyone else gets the summary in its tooltip.
 */
function EnvBadge({ env, admin }: { env: string; admin: boolean }) {
  const { data } = useQuery(statusQueryOptions);
  const state = data ? SEALING[data.sealing] : null;
  const label = `Environment ${env}${state ? `: ${state.label}` : ""}`;
  const badge = (
    <Badge variant="outline" className="gap-1.5">
      <EnvDot dot={state?.dot} />
      {env}
    </Badge>
  );
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        {admin ? (
          <Link
            to="/$env/fleet"
            params={{ env }}
            aria-label={`${label}. Open the fleet`}
            className="rounded-md focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          >
            {badge}
          </Link>
        ) : (
          <button
            type="button"
            aria-label={label}
            className="cursor-default rounded-md focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          >
            {badge}
          </button>
        )}
      </TooltipTrigger>
      <TooltipContent side="bottom">
        {data?.message ?? "Checking whether sealing works…"}
        {admin && " Open the fleet for detail."}
      </TooltipContent>
    </Tooltip>
  );
}

/**
 * The env badge of someone who may use several envs: it switches between
 * them, and says whether sealing works in this one.
 */
function EnvSwitcher({ env, envs }: { env: EnvAccess; envs: EnvAccess[] }) {
  const { data } = useQuery(statusQueryOptions);
  const navigate = useNavigate();
  const state = data ? SEALING[data.sealing] : null;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          aria-label={`Environment ${env.name}${state ? `: ${state.label}` : ""}. Switch environment`}
          className="rounded-md focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
        >
          <Badge
            variant="outline"
            className="gap-1.5 hover:bg-muted data-[state=open]:bg-muted"
          >
            <EnvDot dot={state?.dot} />
            {env.name}
            <ChevronsUpDown className="h-3 w-3 opacity-60" aria-hidden="true" />
          </Badge>
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-64">
        <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">
          Environments
        </DropdownMenuLabel>
        {envs.map((e) => (
          <DropdownMenuItem
            key={e.name}
            onSelect={() =>
              void navigate({ to: "/$env/secrets", params: { env: e.name } })
            }
            aria-current={e.name === env.name ? "true" : undefined}
          >
            {e.name === env.name ? (
              <Check className="mr-2 h-4 w-4" aria-hidden="true" />
            ) : (
              <span className="mr-2 h-4 w-4" aria-hidden="true" />
            )}
            <span className="font-mono">{e.name}</span>
            {e.admin && (
              <span className="ml-auto text-xs text-muted-foreground">
                admin
              </span>
            )}
          </DropdownMenuItem>
        ))}
        <DropdownMenuSeparator />
        <p className="px-2 py-1.5 text-xs text-muted-foreground">
          {data?.message ?? "Checking whether sealing works…"}
        </p>
        {env.admin && (
          <DropdownMenuItem asChild>
            <Link to="/$env/fleet" params={{ env: env.name }}>
              <Server className="mr-2 h-4 w-4" aria-hidden="true" />
              Open the {env.name} fleet
            </Link>
          </DropdownMenuItem>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function Header() {
  const { user, envs } = useAuth();
  const env = useEnv();
  const logout = useLogout();

  return (
    <header className="sticky top-0 z-10 h-14 w-full border-b border-border bg-background/80 backdrop-blur-md supports-backdrop-filter:bg-background/60">
      <div className="flex h-full items-center justify-between px-4 md:px-8">
        <div className="flex items-center gap-3">
          <Link
            to="/"
            className="flex items-center gap-3 rounded-lg focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
            aria-label="Sealer home"
          >
            <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary shadow-xs">
              <FileLock
                className="h-5 w-5 text-primary-foreground"
                aria-hidden="true"
              />
            </span>
            <span className="hidden text-base font-bold tracking-tight sm:inline">
              Sealer
            </span>
          </Link>
          {env &&
            user &&
            (envs.length > 1 ? (
              <EnvSwitcher env={env} envs={envs} />
            ) : (
              <EnvBadge env={env.name} admin={env.admin} />
            ))}
          {user && env && (
            <nav
              aria-label="Main"
              className="ml-1 flex items-center gap-1 sm:ml-4"
            >
              <NavLink env={env.name}>Secrets</NavLink>
            </nav>
          )}
        </div>

        <div className="flex items-center gap-2">
          {user && <SearchButton />}
          <ThemeToggle />
          {user && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="ghost"
                  className="relative h-8 w-8 rounded-full p-0"
                  aria-label={`Account menu for ${user.login}`}
                >
                  {user.avatar_url ? (
                    <img
                      src={user.avatar_url}
                      alt=""
                      className="h-8 w-8 rounded-full"
                    />
                  ) : (
                    <span className="flex h-8 w-8 items-center justify-center rounded-full bg-muted text-sm font-semibold uppercase">
                      {user.login.slice(0, 1)}
                    </span>
                  )}
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-52">
                <DropdownMenuLabel className="font-normal">
                  <p className="text-sm font-medium">{user.login}</p>
                  {user.name && (
                    <p className="text-xs text-muted-foreground">{user.name}</p>
                  )}
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                {env?.admin && (
                  <>
                    <DropdownMenuItem asChild>
                      <Link to="/$env/fleet" params={{ env: env.name }}>
                        <Server className="mr-2 h-4 w-4" aria-hidden="true" />
                        Fleet
                        <span className="ml-auto text-xs text-muted-foreground">
                          admin
                        </span>
                      </Link>
                    </DropdownMenuItem>
                    <DropdownMenuSeparator />
                  </>
                )}
                <DropdownMenuItem
                  onSelect={() => logout.mutate()}
                  disabled={logout.isPending}
                >
                  <LogOut className="mr-2 h-4 w-4" aria-hidden="true" />
                  Sign out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          )}
        </div>
      </div>
    </header>
  );
}

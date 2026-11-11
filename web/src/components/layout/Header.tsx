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
import type { EnvAccess, SealingStatus } from "@/api/types";
import { useAuth } from "@/lib/auth";
import { useEnv } from "@/lib/env";
import { modKey } from "@/lib/shortcuts";
import { cn } from "@/lib/utils";
import { useLogout } from "@/api/queries/auth";
import { statusQueryOptions } from "@/api/queries/status";

function NavLink({
  env,
  to,
  children,
}: {
  env: string;
  to: "/$env/secrets" | "/$env/fleet";
  children: string;
}) {
  return (
    <Link
      to={to}
      params={{ env }}
      className="inline-flex h-9 items-center rounded-md px-2 text-sm font-medium transition-colors hover:bg-muted hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none sm:px-3"
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
      className="w-9 gap-2 px-0 text-muted-foreground sm:w-64 sm:justify-start sm:px-2.5"
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

/**
 * Whether sealing works, by color and by shape, so it never rests on color
 * alone: a circle when it works, a triangle when some clusters are not
 * ready, a square when it is unavailable, and a ring while it is checked.
 */
const SEALING: Record<
  SealingStatus["sealing"],
  { shape: string; label: string }
> = {
  ready: { shape: "h-2 w-2 rounded-full bg-success", label: "sealing works" },
  degraded: {
    shape: "h-2 w-2.5 bg-warning [clip-path:polygon(50%_0,100%_100%,0_100%)]",
    label: "sealing works, some clusters are not ready",
  },
  unavailable: {
    shape: "h-2 w-2 rounded-[1px] bg-destructive",
    label: "sealing is unavailable",
  },
};

/** The env's sealing state, as a small shape beside its name. */
function EnvDot({ state }: { state: SealingStatus["sealing"] | undefined }) {
  return (
    <span
      className={cn(
        "shrink-0",
        state
          ? SEALING[state].shape
          : "h-2 w-2 rounded-full border border-muted-foreground",
      )}
      data-sealing={state ?? "unknown"}
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
      <EnvDot state={data?.sealing} />
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
            <EnvDot state={data?.sealing} />
            {env.name}
            <ChevronsUpDown
              className="h-3 w-3 text-muted-foreground"
              aria-hidden="true"
            />
          </Badge>
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-64">
        <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">
          Envs
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
            <span className="font-medium">{e.name}</span>
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
              Fleet
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
      <div className="flex h-full items-center justify-between gap-2 px-4 md:px-8">
        <div className="flex min-w-0 items-center gap-2 sm:gap-3">
          <Link
            to="/"
            className="flex shrink-0 items-center gap-3 rounded-lg focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
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
              className="flex items-center gap-0.5 sm:ml-4 sm:gap-1"
            >
              <NavLink env={env.name} to="/$env/secrets">
                Secrets
              </NavLink>
              {env.admin && (
                <NavLink env={env.name} to="/$env/fleet">
                  Fleet
                </NavLink>
              )}
            </nav>
          )}
        </div>

        <div className="flex shrink-0 items-center gap-0.5 sm:gap-2">
          {user && <SearchButton />}
          <ThemeToggle />
          {user && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  className="relative rounded-full p-0"
                  aria-label={`Account menu for ${user.login}`}
                >
                  {user.avatar_url ? (
                    <img
                      src={user.avatar_url}
                      alt=""
                      className="h-9 w-9 rounded-full"
                    />
                  ) : (
                    <span className="flex h-9 w-9 items-center justify-center rounded-full bg-muted text-sm font-semibold uppercase">
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

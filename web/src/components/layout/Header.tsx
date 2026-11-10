import { Link } from "@tanstack/react-router";
import { FileLock, LogOut, Search } from "lucide-react";
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
import { useAuth } from "@/lib/auth";
import { modKey } from "@/lib/shortcuts";
import { useLogout } from "@/api/queries/auth";

function NavLink({
  to,
  children,
}: {
  to: "/fleet" | "/repos";
  children: string;
}) {
  return (
    <Link
      to={to}
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

export function Header() {
  const { user, env } = useAuth();
  const logout = useLogout();

  return (
    <header className="sticky top-0 z-10 h-14 w-full border-b border-border bg-background/80 backdrop-blur-md supports-backdrop-filter:bg-background/60">
      <div className="flex h-full items-center justify-between px-4 md:px-8">
        <div className="flex items-center gap-3">
          <Link
            to="/repos"
            className="flex items-center gap-3 rounded-lg focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
            aria-label="Sealer home"
          >
            <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary shadow-xs">
              <FileLock
                className="h-5 w-5 text-primary-foreground"
                aria-hidden="true"
              />
            </span>
            <span className="text-base font-bold tracking-tight">Sealer</span>
          </Link>
          {env && (
            <Badge variant="outline" aria-label={`Environment ${env}`}>
              {env}
            </Badge>
          )}
          {user && (
            <nav aria-label="Main" className="ml-4 flex items-center gap-1">
              <NavLink to="/repos">Repositories</NavLink>
              <NavLink to="/fleet">Fleet</NavLink>
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

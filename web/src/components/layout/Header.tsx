import { Link } from "@tanstack/react-router";
import { FileLock, LogOut } from "lucide-react";
import { ThemeToggle } from "./ThemeToggle";
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
import { useAuth } from "@/lib/auth";
import { useLogout } from "@/api/queries/auth";

function NavLink({
  to,
  exact = false,
  children,
}: {
  to: "/" | "/repos";
  exact?: boolean;
  children: string;
}) {
  return (
    <Link
      to={to}
      activeOptions={{ exact }}
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

export function Header() {
  const { user, env } = useAuth();
  const logout = useLogout();

  return (
    <header className="sticky top-0 z-10 h-14 w-full border-b border-border bg-background/80 backdrop-blur-md supports-backdrop-filter:bg-background/60">
      <div className="flex h-full items-center justify-between px-4 md:px-8">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary shadow-xs">
            <FileLock
              className="h-5 w-5 text-primary-foreground"
              aria-hidden="true"
            />
          </div>
          <span className="text-base font-bold tracking-tight">Sealer</span>
          {env && (
            <Badge variant="outline" aria-label={`Environment ${env}`}>
              {env}
            </Badge>
          )}
          {user && (
            <nav aria-label="Main" className="ml-4 flex items-center gap-1">
              <NavLink to="/" exact>
                Fleet
              </NavLink>
              <NavLink to="/repos">Repositories</NavLink>
            </nav>
          )}
        </div>

        <div className="flex items-center gap-3">
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

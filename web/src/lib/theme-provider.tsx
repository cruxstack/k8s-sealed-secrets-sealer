import {
  createContext,
  useContext,
  useLayoutEffect,
  useState,
  type ReactNode,
} from "react";

type Theme = "dark" | "light" | "system";

interface ThemeProviderProps {
  children: ReactNode;
  defaultTheme?: Theme;
  storageKey?: string;
}

interface ThemeProviderState {
  /** The choice: a theme, or the system's. */
  theme: Theme;
  /** The theme on screen. */
  resolvedTheme: "dark" | "light";
  setTheme: (theme: Theme) => void;
}

const ThemeProviderContext = createContext<ThemeProviderState | undefined>(
  undefined,
);

const DARK_QUERY = "(prefers-color-scheme: dark)";

function readTheme(storageKey: string, fallback: Theme): Theme {
  try {
    const stored = localStorage.getItem(storageKey);
    if (stored === "dark" || stored === "light" || stored === "system") {
      return stored;
    }
  } catch {
    // storage can be unavailable (private mode, blocked site data)
  }
  return fallback;
}

function systemTheme(): "dark" | "light" {
  return window.matchMedia(DARK_QUERY).matches ? "dark" : "light";
}

/**
 * Put the theme's class on <html>: always .light or .dark, so the CSS for
 * the first paint, which follows the system, stops applying. Transitions
 * are off for the swap, or colors would fade from one theme to the other.
 */
function applyTheme(resolved: "dark" | "light") {
  const root = window.document.documentElement;
  if (root.classList.contains(resolved)) return;
  root.classList.add("theme-switching");
  root.classList.remove("light", "dark");
  root.classList.add(resolved);
  // apply the new colors with transitions off, then turn them back on
  void window.getComputedStyle(root).color;
  window.requestAnimationFrame(() => root.classList.remove("theme-switching"));
}

export function ThemeProvider({
  children,
  defaultTheme = "system",
  storageKey = "sealer-theme",
}: ThemeProviderProps) {
  const [theme, setTheme] = useState<Theme>(() =>
    readTheme(storageKey, defaultTheme),
  );
  const [system, setSystem] = useState(systemTheme);
  const resolvedTheme = theme === "system" ? system : theme;

  useLayoutEffect(() => {
    const mediaQuery = window.matchMedia(DARK_QUERY);
    const onChange = () => setSystem(mediaQuery.matches ? "dark" : "light");
    mediaQuery.addEventListener("change", onChange);
    return () => mediaQuery.removeEventListener("change", onChange);
  }, []);

  // before the browser paints, so the first frame has the class
  useLayoutEffect(() => applyTheme(resolvedTheme), [resolvedTheme]);

  const value = {
    theme,
    resolvedTheme,
    setTheme: (next: Theme) => {
      try {
        localStorage.setItem(storageKey, next);
      } catch {
        // the choice still applies for this page
      }
      setTheme(next);
    },
  };

  return (
    <ThemeProviderContext.Provider value={value}>
      {children}
    </ThemeProviderContext.Provider>
  );
}

export function useTheme() {
  const context = useContext(ThemeProviderContext);
  if (context === undefined) {
    throw new Error("useTheme must be used within a ThemeProvider");
  }
  return context;
}

import {
  createContext,
  useContext,
  useEffect,
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
  theme: Theme;
  setTheme: (theme: Theme) => void;
}

const ThemeProviderContext = createContext<ThemeProviderState | undefined>(
  undefined,
);

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

export function ThemeProvider({
  children,
  defaultTheme = "system",
  storageKey = "sealer-theme",
}: ThemeProviderProps) {
  const [theme, setTheme] = useState<Theme>(() =>
    readTheme(storageKey, defaultTheme),
  );

  useEffect(() => {
    const root = window.document.documentElement;
    root.classList.remove("light", "dark");

    if (theme === "system") {
      const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
      const applySystemTheme = () => {
        root.classList.remove("light", "dark");
        root.classList.add(mediaQuery.matches ? "dark" : "light");
      };
      applySystemTheme();
      mediaQuery.addEventListener("change", applySystemTheme);
      return () => {
        mediaQuery.removeEventListener("change", applySystemTheme);
      };
    }

    root.classList.add(theme);
  }, [theme]);

  const value = {
    theme,
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

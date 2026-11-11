/// <reference types="vitest/config" />
import path from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { tanstackRouter } from "@tanstack/router-plugin/vite";

// The control plane embeds internal/webui/dist (go:embed). The build goes
// into its app/ subfolder so emptying it leaves the directory's committed
// placeholder alone.
const outDir = path.resolve(import.meta.dirname, "../internal/webui/dist/app");

export default defineConfig({
  plugins: [
    tanstackRouter({ target: "react", autoCodeSplitting: true }),
    react(),
    tailwindcss(),
  ],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "./src"),
    },
  },
  build: {
    outDir,
    emptyOutDir: true,
    assetsDir: "assets",
  },
  server: {
    // loopback by default; set VITE_DEV_HOST=0.0.0.0 to expose it
    host: process.env.VITE_DEV_HOST ?? "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": {
        target: `http://localhost:${process.env.SEALER_CONTROL_PLANE_PORT ?? "4100"}`,
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    // the palette's test reads index.css as text; other CSS stays out
    css: { include: [/src\/index\.css/] },
  },
});

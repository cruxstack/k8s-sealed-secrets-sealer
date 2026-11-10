import { createFileRoute, redirect } from "@tanstack/react-router";
import { homeEnv } from "@/lib/require-auth";

// pages are under their env now; links from before go to the first env
export const Route = createFileRoute("/secrets/")({
  beforeLoad: async (opts) => {
    const env = await homeEnv(opts);
    throw redirect({ to: "/$env/secrets", params: { env }, replace: true });
  },
});

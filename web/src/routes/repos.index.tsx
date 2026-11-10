import { createFileRoute, redirect } from "@tanstack/react-router";
import { homeEnv } from "@/lib/require-auth";

// the sealing area moved to /{env}/secrets
export const Route = createFileRoute("/repos/")({
  beforeLoad: async (opts) => {
    const env = await homeEnv(opts);
    throw redirect({ to: "/$env/secrets", params: { env }, replace: true });
  },
});

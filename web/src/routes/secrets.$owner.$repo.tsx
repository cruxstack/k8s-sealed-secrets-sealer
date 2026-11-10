import { createFileRoute, redirect } from "@tanstack/react-router";
import { homeEnv } from "@/lib/require-auth";
import { repoSearch } from "./$env.secrets.$owner.$repo";

// pages are under their env now; links from before go to the first env
// and keep their file
export const Route = createFileRoute("/secrets/$owner/$repo")({
  validateSearch: repoSearch,
  beforeLoad: async (opts) => {
    const env = await homeEnv(opts);
    throw redirect({
      to: "/$env/secrets/$owner/$repo",
      params: { env, ...opts.params },
      search: opts.search,
      replace: true,
    });
  },
});

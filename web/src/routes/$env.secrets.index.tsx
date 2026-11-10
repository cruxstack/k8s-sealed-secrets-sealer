import { createFileRoute } from "@tanstack/react-router";
import { RepoList } from "@/components/repos/RepoList";
import { SignedInPage } from "@/lib/require-auth";

export const Route = createFileRoute("/$env/secrets/")({
  component: ReposPage,
});

function ReposPage() {
  return (
    <SignedInPage>
      <RepoList />
    </SignedInPage>
  );
}

import { createFileRoute } from "@tanstack/react-router";
import { RepoList } from "@/components/repos/RepoList";
import { requireSignedIn, SignedInPage } from "@/lib/require-auth";

export const Route = createFileRoute("/repos/")({
  beforeLoad: requireSignedIn,
  component: ReposPage,
});

function ReposPage() {
  return (
    <SignedInPage>
      <RepoList />
    </SignedInPage>
  );
}

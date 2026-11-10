import { createFileRoute } from "@tanstack/react-router";
import { RepoFiles } from "@/components/repos/RepoFiles";
import { requireSignedIn, SignedInPage } from "@/lib/require-auth";

export const Route = createFileRoute("/repos/$owner/$repo")({
  beforeLoad: requireSignedIn,
  component: RepoPage,
});

function RepoPage() {
  const { owner, repo } = Route.useParams();
  return (
    <SignedInPage>
      <RepoFiles owner={owner} repo={repo} />
    </SignedInPage>
  );
}

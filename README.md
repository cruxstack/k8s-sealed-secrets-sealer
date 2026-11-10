# k8s-sealed-secrets-sealer

One web app per environment for sealing Kubernetes secrets with
[Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets), however many
clusters and regions that environment spans. Users pick a repository and a
file, type a value, and get a pull request. They never pick a cluster, a
region or a certificate.

> **Status:** early development. People sign in with GitHub, browse the
> SealedSecrets for their env in the repositories they can read, seal values
> into them as pending changes, and open a pull request with those changes;
> an agent seals each value with the env key, and only `spec.encryptedData`
> changes in the files. A value that differs by region can be sealed for
> some regions' documents only. Optional annotations tell them what a secret
> is for, which keys it should hold and where its docs are. Admins see the fleet
> (every agent, its controller's keys and the env's key state); everyone else
> sees whether sealing works. Agents keep every cluster holding the same keys.
> Releases publish the control plane for Lambda, container images and Helm
> charts; the Terraform module for AWS is next. See
> [the design](docs/design.md) for where it is going.

## How it works

```mermaid
flowchart TB
  user(["Browser"])
  github["GitHub App<br/>read files, open PRs"]

  subgraph env["One control plane per env: sealer.dev.example.com"]
    cp["Control plane<br/>Lambda or container"]
    ddb[("DynamoDB<br/>agents, keys, commands, sessions")]
    kms["KMS keys<br/>transit, escrow"]
  end

  subgraph c1["Cluster use1/blue"]
    a1["agent"] -->|Kubernetes API| s1["sealed-secrets controller"]
  end
  subgraph c2["Cluster use1/green"]
    a2["agent"] -->|Kubernetes API| s2["sealed-secrets controller"]
  end
  subgraph c3["Cluster use2/blue"]
    a3["agent"] -->|Kubernetes API| s3["sealed-secrets controller"]
  end

  user -->|HTTPS| cp
  cp --> ddb
  cp --> kms
  cp --> github
  a1 & a2 & a3 -->|"HTTPS, outbound only"| cp
```

Agents always open the connection; nothing calls into a cluster, and the
controllers never talk to the control plane.

- **Control plane:** serves the UI and API for one environment. Runs on AWS
  Lambda behind API Gateway, or as a container. It has no Kubernetes client
  and knows nothing about the cluster it runs in.
- **Agents:** one per cluster, beside the sealed-secrets controller. They only
  make outbound calls. They report the controller's keys, seal values and keep
  every cluster in the environment holding the same keys.
- **Security:** values travel to agents encrypted with a KMS key the control
  plane can only encrypt with. Sealing keys are escrowed under a KMS key the
  control plane cannot use at all. Agents run with namespaced RBAC, and what
  each agent may do is set in its Helm values, never by the control plane.

Read [docs/design.md](docs/design.md) for the full design and security model.

## Quick start (local)

Requirements: Docker and [Atmos](https://atmos.tools) 1.233 or later. Atmos
installs every other tool (Go, k3d, Tilt, Helm, kubectl) into `.tools/`.

```sh
atmos dev up        # k3d cluster + Tilt dashboard at http://localhost:10350
open http://localhost:4100   # sign in as alice (a GitHub mock)
atmos dev status    # pods, each agent's controller key, endpoints
atmos test e2e      # the end-to-end suite in a throwaway cluster
```

See [docs/development.md](docs/development.md) for the local stack and every
command.

## Install

Each [release](https://github.com/cruxstack/k8s-sealed-secrets-sealer/releases)
publishes:

| Artifact                 | Where                                                                                    |
| ------------------------ | ---------------------------------------------------------------------------------------- |
| Control plane for Lambda | `k8s-sealed-secrets-sealer-lambda_arm64.zip` and `_amd64.zip` on the release             |
| Control plane image      | `ghcr.io/cruxstack/k8s-sealed-secrets-sealer-control-plane:<version>`                    |
| Agent image              | `ghcr.io/cruxstack/k8s-sealed-secrets-sealer-agent:<version>`                            |
| Agent chart              | `oci://ghcr.io/cruxstack/charts/k8s-sealed-secrets-sealer-agent`                         |
| Control plane chart      | `oci://ghcr.io/cruxstack/charts/k8s-sealed-secrets-sealer-control-plane`, for containers |

Install the agent in each cluster, beside its sealed-secrets controller:

```sh
helm install sealer-agent oci://ghcr.io/cruxstack/charts/k8s-sealed-secrets-sealer-agent \
  --version <version> --namespace sealer --create-namespace -f values.yaml
```

Every file, image and chart has a build provenance attestation:

```sh
gh attestation verify k8s-sealed-secrets-sealer-lambda_arm64.zip --repo cruxstack/k8s-sealed-secrets-sealer
gh attestation verify oci://ghcr.io/cruxstack/k8s-sealed-secrets-sealer-agent:<version> \
  --repo cruxstack/k8s-sealed-secrets-sealer
```

## Repository layout

| Path                         | Contents                                         |
| ---------------------------- | ------------------------------------------------ |
| `cmd/server`, `cmd/lambda`   | Control plane as an HTTP server and on Lambda    |
| `cmd/agent`                  | The agent                                        |
| `web/`                       | The web UI, built into the control plane         |
| `internal/`                  | Application packages                             |
| `deploy/helm/`               | Helm charts for the agent and the control plane  |
| `dev/`, `Tiltfile`           | The local k3d stack                              |
| `.atmos/`, `atmos.yaml`      | Developer and CI commands                        |
| `docs/`                      | Design and development guides                    |

AWS infrastructure for the control plane (API Gateway, Lambda, DynamoDB, KMS)
lives in a companion Terraform module repository,
`terraform-aws-k8s-sealed-secrets-sealer`.

## License

MIT. See [LICENSE](LICENSE).

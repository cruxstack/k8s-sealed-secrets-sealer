# -*- mode: Python -*-
# Local stack: one k3d cluster holding the control plane, local AWS emulators
# and several simulated clusters (see dev/stack.yaml). Start it with
# `atmos dev up`, which creates the cluster and pulls the controller chart
# before running Tilt.

# ================================================================== globals ===

STACK = read_yaml("dev/stack.yaml")
SYSTEM_NAMESPACE = "sealer-system"
CHART_DIR = os.getenv("SEALED_SECRETS_CHART_DIR", "")
CONTROL_PLANE_PORT = int(os.getenv("SEALER_CONTROL_PLANE_PORT", "4100"))
DYNAMODB_PORT = int(os.getenv("SEALER_DYNAMODB_PORT", "4102"))
KMS_PORT = int(os.getenv("SEALER_KMS_PORT", "4103"))
GITHUB_PORT = int(os.getenv("SEALER_GITHUB_PORT", "4104"))

# This stack's URLs as a browser on this machine sees them. They are the
# OAuth redirect targets and the agents' token audience, so worktree and e2e
# stacks on other ports still work.
PUBLIC_URL = "http://localhost:%d" % CONTROL_PLANE_PORT
GITHUB_URL = "http://localhost:%d" % GITHUB_PORT

LABEL_BUILD = "build"
LABEL_SETUP = "setup"
LABEL_PLATFORM = "control-plane"

# ====================================================================== fns ===

def validate():
    context = k8s_context()
    if not context.startswith("k3d-sealer"):
        fail("This Tiltfile only runs against the local k3d-sealer* clusters; got '%s'. Run `atmos dev up`." % context)
    if not CHART_DIR or not os.path.exists(CHART_DIR + "/Chart.yaml"):
        fail("The sealed-secrets chart is missing. Run `atmos dev up`, which pulls and verifies it.")
    allow_k8s_contexts(context)

def selector(obj):
    namespace = obj["metadata"].get("namespace", "")
    parts = [obj["metadata"]["name"], obj["kind"].lower()]
    if namespace:
        parts.append(namespace)
    return ":".join(parts)

def is_workload(obj):
    return obj["kind"] in ["Deployment", "Service"]

def namespace(name):
    return {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name}}

def controller_own_namespace_rbac(ns):
    # The chart's Roles cover additionalNamespaces only; the controller also
    # watches SealedSecrets, and the Secrets it would unseal, in its own
    # namespace (the same rules the chart grants elsewhere).
    rules = [
        {"apiGroups": ["bitnami.com"], "resources": ["sealedsecrets"], "verbs": ["get", "list", "watch"]},
        {"apiGroups": ["bitnami.com"], "resources": ["sealedsecrets/status"], "verbs": ["update"]},
        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list", "watch", "create", "update", "delete"]},
        {"apiGroups": [""], "resources": ["events"], "verbs": ["create", "patch"]},
    ]
    return [
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"name": "sealed-secrets-own-namespace", "namespace": ns},
            "rules": rules,
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {"name": "sealed-secrets-own-namespace", "namespace": ns},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "sealed-secrets-own-namespace"},
            "subjects": [{"kind": "ServiceAccount", "name": "sealed-secrets-controller", "namespace": ns}],
        },
    ]

# =================================================================== script ===

validate()
update_settings(max_parallel_updates=6, k8s_upsert_timeout_secs=180)

setup_objects = [namespace(SYSTEM_NAMESPACE)]
workload_objects = []

def add(objs):
    for obj in objs:
        if is_workload(obj):
            workload_objects.append(obj)
        else:
            setup_objects.append(obj)

# ------------------------------------------------------------------- build ---

local_resource(
    "web",
    cmd="bash .atmos/scripts/dev/web.sh",
    deps=["web/src", "web/index.html", "web/public", "web/package.json", "web/package-lock.json", "web/vite.config.ts"],
    labels=[LABEL_BUILD],
)

local_resource(
    "binaries",
    cmd="bash .atmos/scripts/dev/build.sh",
    deps=["cmd", "internal", "go.mod", "go.sum"],
    # the control plane embeds the UI build (internal/webui/dist/app)
    resource_deps=["web"],
    labels=[LABEL_BUILD],
)

for image, binary in [
    ("local.invalid/sealer-control-plane", "server"),
    ("local.invalid/sealer-agent", "agent"),
    ("local.invalid/sealer-mock-github", "mock-github"),
]:
    docker_build(
        image,
        context=".tools/build",
        dockerfile="dev/docker/Dockerfile",
        build_args={"BINARY": binary},
        only=[binary],
    )

# ----------------------------------------------------------- control plane ---

def agent_registry():
    # The registry lists one agent per simulated cluster, logging in with its
    # service account. All of them share the k3d cluster's token issuer, whose
    # signing keys are read once here so the control plane needs no access to
    # the Kubernetes API.
    context = k8s_context()
    discovery = decode_json(str(local("kubectl --context %s get --raw /.well-known/openid-configuration" % shlex.quote(context), quiet=True)))
    jwks = str(local("kubectl --context %s get --raw /openid/v1/jwks" % shlex.quote(context), quiet=True))
    registry = {
        "issuers": [{"name": "local", "url": discovery["issuer"], "jwksFile": "local-jwks.json"}],
        "agents": [
            {
                "id": c["name"],
                "cluster": c["name"],
                "region": c["region"],
                "capabilities": ["seal", "keys", "renewal"],
                "identity": {"k8s": {
                    "issuer": "local",
                    "subject": "system:serviceaccount:%s-sealer:sealer-agent" % c["name"],
                }},
            }
            for c in STACK["clusters"]
        ],
    }
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "sealer-registry", "namespace": SYSTEM_NAMESPACE},
        "data": {"registry.yaml": str(encode_yaml(registry)), "local-jwks.json": jwks},
    }

setup_objects.append(agent_registry())
setup_objects.append({
    "apiVersion": "v1",
    "kind": "ConfigMap",
    "metadata": {"name": "local-kms-seed", "namespace": SYSTEM_NAMESPACE},
    "data": {"seed.yaml": str(read_file("dev/local-kms/seed.yaml"))},
})
setup_objects.extend(decode_yaml_stream(read_file("dev/k3d/control-plane-secret.yaml")))
add(decode_yaml_stream(read_file("dev/k3d/emulators.yaml")))
def mock_github():
    # register this stack's callback URL with the mock, as an OAuth app would
    objs = decode_yaml_stream(read_file("dev/k3d/mock-github.yaml"))
    for obj in objs:
        if obj["kind"] != "Deployment":
            continue
        for container in obj["spec"]["template"]["spec"]["containers"]:
            for e in container.get("env", []):
                if e["name"] == "MOCK_GITHUB_CALLBACK_URLS":
                    e["value"] = PUBLIC_URL + "/api/v1/auth/callback"
    return objs

add(mock_github())
add(decode_yaml_stream(helm(
    "deploy/helm/control-plane",
    name="sealer-control-plane",
    namespace=SYSTEM_NAMESPACE,
    values=["dev/values/control-plane.yaml"],
    set=["publicURL=" + PUBLIC_URL, "github.url=" + GITHUB_URL],
)))

# --------------------------------------------------------- simulated clusters ---

setup_objects.extend(decode_yaml_stream(read_file(CHART_DIR + "/crds/bitnami.com_sealedsecrets.yaml")))

for cluster in STACK["clusters"]:
    name = cluster["name"]
    controller_ns = name + "-sealed-secrets"
    agent_ns = name + "-sealer"
    apps_ns = name + "-apps"
    setup_objects.extend([namespace(controller_ns), namespace(agent_ns), namespace(apps_ns)])
    setup_objects.extend(controller_own_namespace_rbac(controller_ns))

    controller = decode_yaml_stream(helm(
        CHART_DIR,
        name="sealed-secrets",
        namespace=controller_ns,
        values=["dev/values/sealed-secrets.yaml"],
        set=[
            "additionalNamespaces={%s}" % apps_ns,
            # the chart's args value replaces its defaults, so repeat the ones
            # we keep. Renewal starts off everywhere, so the control plane turns
            # it on in exactly one cluster (docs/design.md, "Key renewal").
            "args={--update-status,--key-prefix,sealed-secrets-key,--key-renew-period=0,--all-namespaces=false,--additional-namespaces,%s}" % apps_ns,
        ],
    ))
    add([o for o in controller if o["kind"] != "CustomResourceDefinition"])

    add(decode_yaml_stream(helm(
        "deploy/helm/agent",
        name="sealer-agent",
        namespace=agent_ns,
        values=["dev/values/agent.yaml"],
        set=["controller.namespace=" + controller_ns, "identity.audience=" + PUBLIC_URL],
    )))

# --------------------------------------------------------------- resources ---

k8s_yaml(encode_yaml_stream(setup_objects + workload_objects))

k8s_resource(
    new_name="setup",
    objects=[selector(o) for o in setup_objects],
    labels=[LABEL_SETUP],
)

k8s_resource(
    "local-kms",
    port_forwards=["%d:8080" % KMS_PORT],
    resource_deps=["setup"],
    labels=[LABEL_PLATFORM],
)
k8s_resource(
    "dynamodb-local",
    port_forwards=["%d:8000" % DYNAMODB_PORT],
    resource_deps=["setup"],
    labels=[LABEL_PLATFORM],
)
k8s_resource(
    "mock-github",
    port_forwards=["%d:8080" % GITHUB_PORT],
    resource_deps=["setup", "binaries"],
    labels=[LABEL_PLATFORM],
)
k8s_resource(
    "sealer-control-plane",
    port_forwards=["%d:8080" % CONTROL_PLANE_PORT],
    resource_deps=["setup", "binaries", "local-kms", "dynamodb-local", "mock-github"],
    labels=[LABEL_PLATFORM],
)

for cluster in STACK["clusters"]:
    name = cluster["name"]
    k8s_resource(
        "sealed-secrets-controller:deployment:%s-sealed-secrets" % name,
        new_name=name + "-controller",
        resource_deps=["setup"],
        labels=[name],
    )
    k8s_resource(
        "sealer-agent:deployment:%s-sealer" % name,
        new_name=name + "-agent",
        resource_deps=["setup", "binaries", name + "-controller", "sealer-control-plane"],
        labels=[name],
    )

# Operations

This guide covers running a deployment once it is up
([deployment.md](deployment.md)): the admin API and what to watch, size
limits and cost, upgrades, backups and restore, and troubleshooting.
[The design](design.md) explains why things work as they do.

## Admin API

The admin API gives automation, such as monitoring, an env's fleet without
a GitHub sign-in. It exists only when `APP_ADMIN_TOKEN` is set (in the
control plane chart, through `existingSecret`) or an env sets its own
`adminToken`, and a token must be at least 32 bytes. `APP_ADMIN_TOKEN`
reaches every env that doesn't set its own; an env's `adminToken` reaches
only that env. Besides reading the fleet, a token can revoke and reinstate
keys; nothing else in the admin API changes anything.

| Route                                                        | Answers                                              |
| ------------------------------------------------------------ | ---------------------------------------------------- |
| `GET /api/v1/envs/{env}/admin/fleet`                         | The env's fleet                                      |
| `GET /api/v1/admin/fleet`                                    | The same, when the control plane serves a single env |
| `POST /api/v1/envs/{env}/admin/keys/{fingerprint}/revoke`    | Revokes a key (see "A compromised key")              |
| `POST /api/v1/envs/{env}/admin/keys/{fingerprint}/reinstate` | Reinstates a revoked key                             |
| `GET /healthz`, `GET /readyz`                                | `200` while the process runs; no token               |

```sh
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://sealer.example.com/api/v1/envs/prod/admin/fleet
```

It answers `401` without the right token, and `404` when the admin API is
off or the control plane does not serve the env. Signed-in admins of an env
read the same fleet at `GET /api/v1/envs/{env}/fleet`, and everyone the env
admits reads `GET /api/v1/envs/{env}/status`: whether sealing works, and
how many clusters are ready.

The fleet, with one agent:

```json
{
  "env": "prod",
  "env_key": {
    "fingerprint": "SHA256:...",
    "not_before": "2026-10-01T00:00:00Z",
    "not_after": "2036-09-29T00:00:00Z"
  },
  "keys_in_sync": true,
  "agents": [
    {
      "id": "prod-use1-blue",
      "cluster": "prod-use1-blue",
      "region": "use1",
      "registered_capabilities": ["seal", "keys", "renewal"],
      "checked_in": true,
      "healthy": true,
      "in_scope": true,
      "last_checkin": "2026-11-10T12:00:00Z",
      "agent_version": "0.6.0",
      "capabilities": ["keys", "renewal", "seal"],
      "commands": ["keys.restore.v1", "renewal.enable.v1", "seal.v1"],
      "controller": {
        "namespace": "sealed-secrets",
        "name": "sealed-secrets-controller",
        "key_renew_period": "720h0m0s",
        "key_order_priority": "CertNotBefore",
        "active_fingerprint": "SHA256:..."
      },
      "keys": [{ "fingerprint": "SHA256:...", "not_before": "...", "not_after": "..." }],
      "keys_complete": true
    }
  ]
}
```

| Field           | Meaning                                                      |
| --------------- | ------------------------------------------------------------ |
| `env_key`       | The key every in-scope cluster holds, which seals use; null  |
|                 | when there is none, and sealing is paused.                   |
| `healthy`       | The agent checked in recently.                               |
| `in_scope`      | The cluster counts for the env key: it has checked in, and   |
|                 | its controller orders keys by `CertNotBefore`.               |
| `capabilities`  | What the agent reported and its registry entry allows.       |
| `keys_complete` | The agent reported its controller's whole key set; false     |
|                 | without the `keys` capability.                               |
| `missing_keys`  | Keys other in-scope clusters hold and this one lacks. Left   |
|                 | out when there are none.                                     |
| `issues`        | Why the agent needs attention, in words. Left out when there |
|                 | are none.                                                    |

### What to watch

Problems with no request behind them, such as an agent that stops checking
in, show only in the fleet, so poll it rather than wait for a log event.
Alert when, for more than a few minutes:

- `env_key` is null: nothing can be sealed in the env;
- an agent is not `healthy`, or has `missing_keys` or `issues`.

Alert, too, on these log events, at warn level or above:

- control plane: `key.sync_failed`, `key.escrow_rejected`,
  `renewal.enable_failed`, `agent.login_rejected`,
  `agent.checkin_rejected`, `seal.invalid_result`,
  `repo.permission_mismatch`;
- agents: `agent.checkin_failed`, `agent.poll_failed`,
  `controller.read_failed`, `controller.key_unusable`,
  `controller.active_key_unlabeled`, `controller.cert_expired`,
  `key.sync_failed`.

`key.discovered` marks every new sealing key. One is expected after each
renewal (design section 9); any other deserves a look. The design lists
the events that make up the audit trail, and how long to keep them
(section 11).

## Size limits

| Limit                         | Applies to                 | Allows                       |
| ----------------------------- | -------------------------- | ---------------------------- |
| KMS key policy: 32 KB         | Each transit key, primary  | Roughly 70 to 100 agents, a  |
|                               | and each replica           | statement each; one tagged   |
|                               |                            | statement for more           |
| SSM parameter: 4 KB, or 8 KB  | A registry given as a      | About 20 agents, or 40; a    |
| in the advanced tier          | parameter                  | file for more                |
| Lambda environment: 4 KB in   | `APP_ENVS` and other       | Larger settings as SSM       |
| all                           | settings on Lambda         | parameter ARNs               |
| ConfigMap: 1 MiB              | The chart's registry       | Thousands of agents          |
| DynamoDB item: 400 KB         | A seal                     | A value of 64 KiB, and 224   |
|                               |                            | KiB with its targets         |
| API Gateway: 30 seconds       | Every request              | Command polls of 20 seconds  |

[deployment.md](deployment.md) shows the tagged key policy statement
(step 1) and registry files (step 3).

## Cost and scale

On Lambda, an agent costs mostly the invocation it holds: it polls for
commands with a 20-second wait, one poll after another, so one invocation
per agent runs all the time, and Lambda bills that time. Per agent, per
month, at AWS's us-east-1 list prices (Lambda arm64 $0.0000133 per
GB-second, HTTP API $1 per million requests, DynamoDB on demand $0.125 per
million read units and $0.625 per million write units), with a handful of
keys per cluster:

| Item                                                        | Roughly              |
| ----------------------------------------------------------- | -------------------- |
| Lambda, the held poll, with 128 MB of memory                | $4.40                |
| Lambda, the held poll, with 256 MB of memory                | $8.80                |
| API Gateway: a poll every 20 seconds, a check-in every 15   | $0.30                |
| DynamoDB: the held poll queries the agent's commands twice  | $0.65                |
| a second (strongly consistent)                              |                      |
| DynamoDB: each check-in writes the agent's state and reads  | $0.25 + $0.02 × N    |
| every agent's, N in all                                     |                      |

So an agent costs about $6 to $10 a month in an env of 10 agents, and
about $2 more in one of 100. The check-in reads grow with the square of
the env's agents. In a container, the held polls cost nothing extra: one
process holds them all, and the DynamoDB costs are the same.

Each held poll is also one of Lambda's concurrent executions, all the time,
counted against the function and against the account's concurrency in the
region (1,000 by default), which every function there shares. Agents'
polls can then crowd out people's requests, or other functions'.

- **Past about 50 agents, run the control plane in a container.** Below
  that, the difference is tens of dollars a month, and Lambda needs no
  cluster. Past it, it is hundreds, and the concurrency adds up.
- **On Lambda, give `/agent/*` a function of its own.** Deploy the same
  package with the same settings as a second function (it keeps no state,
  so either serves any request), route `/agent/{proxy+}` to it in API
  Gateway, and reserve it concurrency of at least the number of agents
  plus room for their check-ins. Reserve the other function what people
  need. With one function, at least reserve it enough for both.

## Upgrades

The control plane and the agents are released together, from one commit,
and tested together. A control plane supports agents up to one minor
version behind it: it accepts agent messages with fields it doesn't know,
and agents name the protocol versions they speak at check-in (design §5).
An agent newer than its control plane isn't supported, so upgrade the
control plane first. An agent that is refused stops sealing and key sync
in its cluster until it is upgraded; decryption does not stop, since
controllers never need the control plane.

- Read the release notes of every version you cross; breaking changes have
  a section of their own.
- Upgrade the control plane, then the agents, within one minor version.
- Keep each env's table across upgrades: it holds the env's escrowed keys.

### To several envs on one URL (v0.6.0)

- Agents before v0.6.0 do not name their env. A control plane serving one
  env still accepts them; one serving several refuses them with `400`.
  Upgrade every agent to v0.6.0 or later, with `env` set, before adding a
  second env.
- Moving the control plane chart from `env` to `envs` changes where the
  existing env's registry is read: `registry-<name>.yaml` instead of
  `registry.yaml` in the registry ConfigMap. Rename the key, or set the
  env's `registryFile: /etc/k8s-sealed-secrets-sealer/registry.yaml`.
- Give the existing env its current table and transit key in `envs`.
- With `APP_ENVS`, each env's agent session key is derived for it, so
  agents' sessions end and they log in again. People's sessions from before
  v0.6.0 name no envs, so people sign in again.

## Backups and restore

### What the table holds

| Items                          | If lost                                         |
| ------------------------------ | ----------------------------------------------- |
| Agent state, key records       | Rebuilt by the agents' next check-ins. Only     |
|                                | which agent first reported a key, and when, is  |
|                                | lost.                                           |
| Escrowed keys                  | Uploaded again by any agent with `keys` whose   |
|                                | cluster still holds the key, on its next        |
|                                | check-in.                                       |
| Commands, sessions, seals and  | Lost: seals in flight fail, and people seal     |
| pending changes                | their pending changes again. All of it expires  |
|                                | within hours anyway.                            |
| Login replay records           | Short-lived; nothing to do.                     |

So escrow is the only state that cannot be rebuilt, and only for a key that
no running cluster with the `keys` capability holds any more: after losing
an env's only cluster, say, or every cluster in a region.

### Restoring the table

Point-in-time recovery, and an AWS Backup restore, create a new table; they
cannot overwrite the old one. So a restore is a configuration change:

1. Restore to a new table name (`sealer-prod-restored`), with the same
   customer-managed KMS key.
2. On the new table, turn on TTL on `expires_at` and point-in-time
   recovery, and add it to the backup plan: a restore copies none of them.
3. Give the control plane's role its DynamoDB actions on the new table.
4. Set the env's `dynamodbTable` (or `APP_DYNAMODB_TABLE`) to it, and
   deploy.
5. Watch the fleet: agents check in, upload the keys the table lacks, and
   restore the keys their clusters lack.

Anything after the restore point is gone: sessions and pending changes,
and escrow uploads, which agents make again for keys their clusters hold.
If the table and its backups are both lost, a new empty table (created as
in [deployment.md](deployment.md#4-the-control-plane-in-the-tools-account),
then steps 3 to 5) rebuilds the same way, except for keys no running
cluster holds.

### Losing a region

Clusters never need the control plane to decrypt: they keep running with
the keys they hold. What stops is sealing and key sync. A cluster that has
lost its keys, such as a rebuilt one, gets them back only through the
control plane, its table and the escrow key, so those come back first.
Keep copies of the table in another region with AWS Backup's cross-region
copies, and the escrow key multi-Region with a replica there
(deployment.md, step 1). The escrow key's break-glass role (design section
8) can decrypt escrowed keys, but no tool restores them without the control
plane yet.

### A rebuilt cluster

A rebuilt cluster's controller starts with a fresh key and none of the
env's. Its agent gets them from escrow:

1. Keep its registry entry, and give the new cluster the same identity:
   associate the agent's IAM role with the new cluster's service account
   or, with k8s-oidc, update the issuer's `url` and keys in the registry,
   since a new cluster has new signing keys and often a new issuer URL.
2. Install the agent with the `keys` capability, in its values and its
   registry entry, beside a controller that orders keys by `CertNotBefore`
   (its default).
3. The control plane queues `keys.restore.v1` for the escrowed keys the
   cluster lacks; the agent restores them and restarts the controller once.
   The cluster's own new key is escrowed and restored into the others in
   turn, restarting each of their controllers once.

Values sealed before the rebuild decrypt there once the restore is done.
For its first 30 minutes the cluster is joining: the env keeps sealing with
the key the other clusters share, and the fleet view shows it joining. If it
hasn't caught up by then, or its agent can't restore, it counts again and
the fleet view says it holds back the env key (design §7).

### A compromised key

Revoke it, from the fleet page's Keys table or with the admin API
(`POST /api/v1/envs/{env}/admin/keys/{fingerprint}/revoke`). A revoked key
is never the env key and is never restored into a cluster again; clusters
that hold it keep it, so values sealed with it still decrypt. Revoking
doesn't make those values secret again: rotate them, and seal the new
values. If the revoked key was the newest, the env falls back to the newest
key every cluster still shares; to get a fresh one, let a controller renew
or restart one with its key Secrets relabelled, as the sealed-secrets docs
describe. Reinstate a key revoked by mistake the same way.

## Troubleshooting

**A seal is refused with "keys out of sync", or the env says sealing is
paused while key sync catches up.** No key is held by every in-scope
cluster. The fleet's `missing_keys` names what each cluster lacks, and
restores normally close the gap within a few check-ins. If they do not:

- the agent lacks `keys`, in its Helm values or its registry entry, so it
  can neither upload nor restore keys;
- no agent holding the missing key has `keys`, so it was never escrowed;
- a restore failed: `key.sync_failed`, in the control plane's and the
  agent's logs, says why (an escrow key policy that does not allow the
  agent's role, for example). A failed restore is retried 5 minutes later.

"No cluster has reported a sealing key yet" means no agent has checked in.

**"no agent is available to seal".** No agent is healthy, has `seal` and
holds the env key. The fleet's `healthy` and `issues` say which part is
missing; an agent's `/readyz` says whether its check-ins succeed.

**An agent logs "control plane rejected the agent's credentials" (401).**
The control plane logs `agent.login_rejected` with the reason. Usually:

- the identity is not in that env's registry: the role's account and name,
  or the issuer and service account subject;
- the audience differs: the agent's `identity.audience` (by default
  `controlPlane.url`) must equal the control plane's `agentAudience` (by
  default `publicURL`);
- aws-sts: the STS host is not allowed (`aws.stsHosts`), the control plane
  cannot reach STS, or the clocks are more than 15 minutes apart;
- k8s-oidc: the issuer's `url` differs from the tokens' `iss`, or a
  `jwksFile` holds old keys.

**`400`: "this control plane serves several envs: name the agent's env in
X-K8s-Sealed-Secrets-Sealer-Env".** The agent is older than v0.6.0. Upgrade
it (see Upgrades).

**An agent's login fails with "not found", or "it serves env X, this agent
belongs to Y".** The agent's `env` names an env the control plane does not
serve (the control plane answers `404`, "does not serve the X env"), or
`controlPlane.url` is another env's control plane. Set `env` to the env
whose registry lists the agent, or fix the URL.

**"the seal and keys capabilities need a KMS region" (agent) or "sealing
needs a KMS region" (control plane).** A key named by ID or alias needs a
region. Name the keys by ARN, as a key in another account must be anyway,
or set `kms.region` (`APP_KMS_REGION`, or an env's `kmsRegion`), or
`AWS_REGION`. "aws-sts identity needs a region" is the same for the login:
set the agent chart's `aws.region`.

**Seals fail on the agent with a KMS access error.** The transit key's
policy, on the key or replica the agent calls, lacks the agent's statement,
or the statement's `agent_id` is not the agent's registry ID.

**Sign-in fails with "You must be a member of a GitHub team allowed to use
one of its envs" (`not_in_team`).** The person is in the org but in no
team that any env admits (`allowedTeams`, the env's own or the shared
ones). Teams are named by their slug, and only active membership counts,
not a pending invitation. If they are in the team, check that the GitHub
App has the organization permission Members (read). The control plane logs
`user.login_rejected` with the user and the reason.

**A person is told they "may not use the prod env".** Their session does
not grant it. Teams are checked at sign-in, so after joining a team they
sign out and in again.

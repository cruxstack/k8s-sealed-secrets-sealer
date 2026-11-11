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
only that env.

A token only reads the fleet, unless the env lets it change keys:
`APP_ADMIN_TOKEN_KEY_CHANGES=true` with a single env (the chart's
`adminTokenKeyChanges`), or `adminTokenKeyChanges: true` on the env in
`APP_ENVS` (the chart's `envs`). Then it revokes, reinstates and deletes
keys too; elsewhere those routes answer `403`. Give an env that allows it
its own `adminToken`, so a token handed to monitoring cannot change its
keys. Signed-in admins change keys from the fleet page either way. Nothing
else in the admin API changes anything. A token also reads reseal
schedules, runs and pull requests, every repository included (see
"Resealing").

| Route                                                        | Answers                                     |
| ------------------------------------------------------------ | ------------------------------------------- |
| `GET /api/v1/envs/{env}/admin/fleet`                         | The env's fleet                             |
| `POST /api/v1/envs/{env}/admin/keys/{fingerprint}/revoke`    | Revokes a key (see "A compromised key"),    |
|                                                              | where the env allows it                     |
| `POST /api/v1/envs/{env}/admin/keys/{fingerprint}/reinstate` | Reinstates a revoked or deleted key, where  |
|                                                              | the env allows it                           |
| `POST /api/v1/envs/{env}/admin/keys/{fingerprint}/delete`    | Deletes a revoked key no value uses (see    |
|                                                              | "Deleting old keys"), where the env allows  |
|                                                              | it; `409` with the reason when it may not   |
| `GET /api/v1/envs/{env}/admin/reseal/schedules`              | The env's reseal schedules                  |
| `GET /api/v1/envs/{env}/admin/reseal/runs`                   | Its runs, newest first (`?schedule=`,       |
|                                                              | `?limit=`, 50 at most)                      |
| `GET /api/v1/envs/{env}/admin/reseal/runs/{id}`              | A run, with every repository                |
| `GET /api/v1/envs/{env}/admin/reseal/pull-requests`          | Its reseal pull requests (`?state=open`,    |
|                                                              | `merged`, `closed` or `all`)                |
| `GET /api/v1/admin/fleet`,                                   | The same, when the control plane serves a   |
| `POST /api/v1/admin/keys/{fingerprint}/revoke`,              | single env                                  |
| `POST /api/v1/admin/keys/{fingerprint}/reinstate`,           |                                             |
| `POST /api/v1/admin/keys/{fingerprint}/delete`,              |                                             |
| `GET /api/v1/admin/reseal/...`                               |                                             |
| `GET /healthz`, `GET /readyz`                                | `200` while the process runs; no token      |

```sh
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://sealer.example.com/api/v1/envs/prod/admin/fleet
```

A fingerprint in a path is `SHA256:` and its base64 in the URL-safe
alphabet, `+` as `-` and `/` as `_`. The standard form, which the fleet
page's copy button copies, works too with each `/` written `%2F`; a bare
`/` splits the path, and the route answers `404`:

```sh
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://sealer.example.com/api/v1/envs/prod/admin/keys/$(printf %s "$FP" | tr '+/' '-_')/revoke"
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
  "no_usable_key": false,
  "key_limit": 250,
  "keys": [
    {
      "fingerprint": "SHA256:...",
      "not_before": "2026-10-01T00:00:00Z",
      "not_after": "2036-09-29T00:00:00Z",
      "holders": ["prod-use1-blue"],
      "escrow_copies": 1,
      "env_key": true,
      "status": "active",
      "purged": false,
      "future_dated": false,
      "references": {
        "values": 12,
        "sealed_secrets": 5,
        "clusters": [
          {
            "agent": "prod-use1-blue",
            "cluster": "prod-use1-blue",
            "values": 12,
            "sealed_secrets": 5,
            "counted_at": "2026-11-10T11:58:00Z"
          }
        ],
        "uncounted": []
      },
      "deletable": false,
      "delete_blocked": "Revoke the key first."
    }
  ],
  "agents": [
    {
      "id": "prod-use1-blue",
      "cluster": "prod-use1-blue",
      "region": "use1",
      "registered_capabilities": ["seal", "keys", "renewal", "cleanup"],
      "checked_in": true,
      "healthy": true,
      "in_scope": true,
      "last_checkin": "2026-11-10T12:00:00Z",
      "agent_version": "0.6.0",
      "capabilities": ["cleanup", "keys", "renewal", "seal"],
      "commands": ["keys.delete.v1", "keys.restore.v1", "renewal.enable.v1", "seal.v1"],
      "controller": {
        "namespace": "sealed-secrets",
        "name": "sealed-secrets-controller",
        "key_renew_period": "720h0m0s",
        "key_order_priority": "CertNotBefore",
        "active_fingerprint": "SHA256:..."
      },
      "keys": [{ "fingerprint": "SHA256:...", "not_before": "...", "not_after": "..." }],
      "keys_complete": true,
      "keys_reported": 1,
      "keys_dropped": 0,
      "joining": false,
      "joined_at": "2026-10-01T09:30:00Z",
      "key_usage": {
        "counted_at": "2026-11-10T11:58:00Z",
        "namespaces": null,
        "sealed_secrets": 5,
        "values": 12,
        "unmatched": 0
      }
    }
  ]
}
```

| Field                  | Meaning                                                    |
| ---------------------- | ---------------------------------------------------------- |
| `env_key`              | The key every in-scope cluster holds, which seals use;     |
|                        | null when there is none, and sealing is paused.            |
| `no_usable_key`        | No env key although no cluster is missing a key: every key |
|                        | the clusters share is revoked or dated in the future, so a |
|                        | new key is needed.                                         |
| `key_limit`            | How many keys of a cluster are kept track of.              |
| `keys`                 | The keys clusters report and the revoked keys, newest      |
|                        | first: who holds each, its escrowed copies, whether it is  |
|                        | the env key, its `status` (`active`, `revoked` with        |
|                        | `revoked_by` and `revoked_at`, or `deleted` with           |
|                        | `deleted_by`, `deleted_at` and `purge_at` as well) and     |
|                        | whether it is dated in the future. A deleted key is left   |
|                        | out once no cluster holds it and it is `purged`.           |
| `references`           | The values sealed with a key, summed over the clusters     |
|                        | that counted within the hour, per cluster, and the agents  |
|                        | that did not count (`uncounted`).                          |
| `deletable`,           | Whether an admin may delete the key now: only a revoked    |
| `delete_blocked`       | key no counted value uses. On every other key, why not, in |
|                        | one sentence, the same a delete is refused with.           |
| `healthy`              | The agent checked in recently.                             |
| `in_scope`             | The cluster counts in key comparison: it has checked in,   |
|                        | and its controller orders keys by `CertNotBefore`, or the  |
|                        | agent cannot tell. A joining cluster is in scope, but left |
|                        | out of the env key.                                        |
| `capabilities`         | What the agent reported and its registry entry allows.     |
| `keys_complete`        | The agent reported its controller's whole key set; false   |
|                        | without the `keys` capability.                             |
| `keys_reported`,       | How many keys the agent reported, and how many of them,    |
| `keys_dropped`         | the oldest, were left out over `key_limit`.                |
| `missing_keys`         | Keys other in-scope clusters hold and this one lacks. Left |
|                        | out when there are none.                                   |
| `joining`, `joined_at` | The cluster joined the env, or was rebuilt, within 30      |
|                        | minutes, and is left out of the env key while restore      |
|                        | gives it the env's keys; and when it joined.               |
| `key_usage`            | The agent's latest count of the values its controller's    |
|                        | SealedSecrets hold: when it came in, the namespaces it     |
|                        | covers (null for every one), how many values no key in the |
|                        | cluster decrypts, or why it failed. Left out without one.  |
| `issues`               | Why the agent needs attention, in words. Left out when     |
|                        | there are none.                                            |

### What to watch

Problems with no request behind them, such as an agent that stops checking
in, show only in the fleet, so poll it rather than wait for a log event.
Alert when, for more than a few minutes:

- `env_key` is null: nothing can be sealed in the env (with
  `no_usable_key`, until a new key reaches every cluster);
- an agent is not `healthy`, or has `missing_keys` or `issues`, and is not
  `joining`: a joining cluster lacks the env's keys, and says so in
  `issues`, until restore catches it up. If it is still missing keys when
  its 30 minutes end, it is no longer joining, and alerts.

Alert, too, on these log events, at warn level or above:

- control plane: `key.sync_failed`, `key.escrow_rejected`,
  `key.escrow_refused`, `key.future_dated`, `keys.near_limit`,
  `keys.truncated`, `keys.out_of_sync`, `key.remove_refused`,
  `key.delete_undone`, `key.unmatched_values`, `key.usage_invalid`,
  `renewal.enable_failed`,
  `agent.login_rejected`, `agent.checkin_rejected`, `seal.invalid_result`,
  `repo.permission_mismatch`, `agent.login_throttled`,
  `registry.reload_failed`, `github.request_failed`, `reseal.failed`,
  `reseal.invalid_result`, `reseal.tick_failed`;
- agents: `agent.checkin_failed`, `agent.poll_failed`,
  `agent.clock_skew`, `controller.read_failed`, `controller.key_unusable`,
  `controller.active_key_unlabeled`, `controller.cert_expired`,
  `controller.restart_failed` (restored keys are not loaded yet),
  `controller.too_many_keys`, `command.panicked`, `command.report_failed`,
  `key.sync_failed`, `key.count_failed`.

`key.discovered` marks every new sealing key. One is expected after each
renewal (design section 9); any other deserves a look. `key.deleted` and
`key.removed` mark keys leaving the env, which only admins start. The
design lists the events that make up the audit trail, and how long to keep
them (section 11).

After `registry.reload_failed` the control plane keeps the registry in
force, so an agent just removed from it keeps its access. The fleet doesn't
show this; only the event does.

Where reseal schedules run, alert too on a run that ends `partial` or
`failed` (`reseal.run_finished` at warn), and on a reseal pull request open
for longer than your review cycle (`GET .../admin/reseal/pull-requests`,
by `opened_at`): while it is open, later runs skip its repository.

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
and tested together. Upgrade the control plane first, then the agents
(design §5 has the rules):

- A control plane supports agents up to one minor version behind it. It
  still speaks the protocol version they name at check-in, and sends them
  only the command types they list.
- An agent newer than its control plane works only where it added nothing
  the control plane must understand. A control plane from v0.6.4 on
  ignores fields it doesn't know in what agents send; an earlier one
  refuses them. Either refuses a new protocol version, capability or
  `key_order_priority` value.

An agent that is refused stops sealing and key sync in its cluster until
the older side is upgraded; decryption does not stop, since controllers
never need the control plane.

- Read the release notes of every version you cross; breaking changes have
  a section of their own.
- Upgrade the control plane, then the agents, within one minor version.
- Keep each env's table across upgrades: it holds the env's escrowed keys.
- Upgrade agents one cluster at a time. An agent's Deployment uses the
  `Recreate` strategy, so two pods never act as one agent: the old pod
  finishes its commands (up to 45 seconds) and stops before the new one
  starts, pulls its image and checks in. Meanwhile the agent does not
  check in, and once its last check-in is older than its health window (45
  seconds at the default interval) it counts as unhealthy. If it is the
  env's only seal-capable agent, seals are refused until it checks in
  again. Pre-pull the new image onto the cluster's nodes before upgrading
  to keep the gap short.
- Before rolling the control plane back to a version that predates
  deleting keys, reinstate every deleted key you may still need. An older
  control plane does not know the deleted status, and leaves the expiry on
  a key's escrowed copies even when it reinstates the key, so they are
  purged all the same.

### To resealing

- Upgrade the control plane first. One that predates resealing refuses the
  check-in of an agent with `reseal`, a capability it does not know.
- Then turn `reseal` on in the agents that should reseal, in their values
  (`capabilities.reseal`, with `keys`) and their registry entries.
- On Lambda, add the tick schedule
  ([deployment](deployment.md#4-the-control-plane-in-the-tools-account)).
  A container ticks on its own (`tickInterval`).
- Nothing else changes: the table keeps its key schema, and the control
  plane's role already has every DynamoDB action resealing uses.

### From v0.7.0 or v0.7.1

- The admin token no longer revokes or reinstates keys unless the env
  allows it: `APP_ADMIN_TOKEN_KEY_CHANGES=true`, or `adminTokenKeyChanges`
  in the chart or on an env in `envs`/`APP_ENVS`. Until then those routes
  answer `403`. Reading the fleet is unchanged, and signed-in admins change
  keys as before.
- Agents now say which escrowed copy a failed restore tried and whether
  the copy was at fault, so only a bad copy is skipped. Agents of v0.7.1
  and before don't, and their failures move them on to the next copy, as
  before.

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
| Revocations (key status and    | Lost: a revoked key counts as active again, can |
| `KEYS`/`REVOKED#` items)       | become the env key and is restored into         |
|                                | clusters. Revoke it again.                      |
| Deletions (the same items, and | Lost: a key deleted since counts as revoked, or |
| escrow copies' `expires_at`)   | active, again, and its escrowed copies no       |
|                                | longer expire. Clusters that removed it are     |
|                                | missing it if it is active: revoke it, and      |
|                                | delete it again.                                |
| Purges                         | Not undone: copies DynamoDB removed are not in  |
|                                | a restore from after they expired. A key whose  |
|                                | copies are gone cannot be restored, though the  |
|                                | restored table may list it as active.           |
| Commands, sessions, seals and  | Lost: seals in flight fail, and people seal     |
| pending changes                | their pending changes again. All of it expires  |
|                                | within hours anyway.                            |
| Session counts, change places  | Written again by the next session or seal; rate |
| and rate windows               | windows last a minute, or ten for the lookups   |
|                                | repository lists make. Nothing to do.           |
| Login replay records           | Short-lived; nothing to do.                     |
| Reseal schedules               | Lost: create them again. Their runs' pull       |
|                                | requests stay on GitHub.                        |
| Runs, reseal pull requests and | Lost: the list of reseal pull requests forgets  |
| file reseals                   | those opened before, and a run no longer skips  |
|                                | a repository for one still open. Close or merge |
|                                | those on GitHub; a run in flight is gone, and   |
|                                | its schedule runs again when next due.          |

So two kinds of state cannot be rebuilt. Escrow, for a key that no running
cluster with the `keys` capability holds any more: after losing an env's
only cluster, say, or every cluster in a region. And revocations, which
only admins make, and only the table records.

### Restoring the table

Point-in-time recovery, and an AWS Backup restore, create a new table; they
cannot overwrite the old one. So a restore is a configuration change:

1. List the env's revoked and deleted keys, to make the revocations and
   deletions again. From the old table, if it can still be read:

   ```sh
   aws dynamodb query --table-name sealer-prod \
     --key-condition-expression 'pk = :pk AND begins_with(sk, :r)' \
     --expression-attribute-values '{":pk":{"S":"KEYS"},":r":{"S":"REVOKED#"}}' \
     --projection-expression 'fingerprint, revoked_by, revoked_at, #s, deleted_at, purge_at' \
     --expression-attribute-names '{"#s":"status"}'
   ```

   Otherwise from the control plane's logs: every `key.revoked`,
   `key.deleted` and `key.reinstated` event, the latest for each
   fingerprint.
2. Restore to a new table name (`sealer-prod-restored`), with the same
   customer-managed KMS key.
3. On the new table, turn on TTL on `expires_at` and point-in-time
   recovery, and add it to the backup plan: a restore copies none of them.
4. Give the control plane's role its DynamoDB actions on the new table.
5. Set the env's `dynamodbTable` (or `APP_DYNAMODB_TABLE`) to it, and
   deploy.
6. Revoke each key from step 1 that the new table does not list as
   revoked, from the fleet page's Keys table, and reinstate any it lists
   that was reinstated since. A key no agent has reported to the new table
   yet is not listed; it is after the agents' next check-in. Until then a
   revoked key can be the env key, but a pull request refuses values
   sealed with it once it is revoked again. Delete again each key step 1
   lists as deleted: once the clusters have counted, the fleet page offers
   it. Its 30 days start again; one past its old `purge_at` can be purged
   by hand instead, by deleting its `ESCROW` items.
7. Watch the fleet: agents check in, upload the keys the table lacks, and
   restore the keys their clusters lack.

Anything after the restore point is gone: sessions and pending changes,
escrow uploads, which agents make again for keys their clusters hold, and
revocations, which step 6 makes again. If the table and its backups are
both lost, a new empty table (created as in
[deployment.md](deployment.md#4-the-control-plane-in-the-tools-account),
then steps 4 to 7, with step 1 from the logs) rebuilds the same way, except
for keys no running cluster holds.

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

Revoke it, from the fleet page's Keys table or, where the env allows it, with
the admin API (`POST /api/v1/envs/{env}/admin/keys/{fingerprint}/revoke`). A
revoked key is never the env key and is never restored into a cluster again;
clusters that hold it keep it, so values sealed with it still decrypt. Seals
still running with it fail, and people with pending changes sealed with it see
them marked "Seal again": their pull request is refused until they seal those
values again or remove them. Pull requests opened before the revocation are not
changed; check open ones for the key's fingerprint, which each lists, shortened.
Revoking doesn't make those values secret again: rotate them, and seal the new
values. If the revoked key was the newest, the env falls back to the newest key
every cluster still shares; if there is none, sealing waits for a new key
(`no_usable_key`). To get a fresh one, let a controller renew or restart one
with its key Secrets relabelled, as the sealed-secrets docs describe. Reinstate
a key revoked by mistake the same way.

An admin's grant is checked at sign-in and kept for the session, 8 hours by
default (`APP_USER_SESSION_TTL`). Someone removed from the admin team, such
as a suspected insider, can still revoke, reinstate and delete keys until
their session ends; shorten the session if that matters. Revocations are kept
only in the env's table; restoring the table loses those made after the
restore point (see "Restoring the table").

### Deleting old keys

Keys pile up over time, one per renewal, and every cluster holds every key.
With the `cleanup` capability on every agent of an env (in its values and
its registry entry), the fleet page shows how many values each key seals,
by cluster. Values still on an old key can be moved onto the env key first
(see "Resealing"). A key no value uses can go:

1. Make sure no value you still need is sealed with it outside the
   clusters: in a branch, an app not deployed yet, or an open pull request.
   Clusters count only what their controllers watch.
2. Revoke it. No new value is sealed with it from then on.
3. Wait for every cluster to count again, a few minutes
   (`keyUsageInterval`), and delete it. The fleet page says what it waits
   for, and refuses while any value uses the key.
4. Each agent removes it from its cluster and restarts its controller;
   `key.removed` names each cluster, and the key's holders empty.

For 30 days its escrowed copies are kept, and reinstating it brings it back
to every cluster. Watch `key.unmatched_values`, and the clusters' issues,
meanwhile: a value applied later that was sealed with the key shows there,
as a value no key in the cluster decrypts. After 30 days the key cannot
come back, unless a cluster still holds it: a cluster that counts values
sealed with a deleted key, or refuses to remove it for them, undoes the
deletion (`key.delete_undone`), and the key is revoked again. Reinstate it
then, and that cluster escrows it again.

### Resealing

Resealing moves values off older keys onto the env key, unchanged (design
section 16), so old keys reach zero references and can be deleted. It
does not rotate values: a value sealed with a key that may be exposed must
be sealed again with a new value, since git history keeps the old
ciphertext. It needs agents with the `reseal` capability (in their values
and registry entries) and, on Lambda, the tick schedule
([deployment](deployment.md#4-the-control-plane-in-the-tools-account)).
`GET .../status` says whether the env can reseal now (`can_reseal`), and
why not: no agent with `reseal` is healthy and holds the env key, or none
of their controllers seals with the env key yet.

- **A file:** an admin who can write to the repository reseals it from a
  session, once its seals have finished, and opens the pull request as
  with any seal. A value sealed in the session always wins over a reseal
  of it. A file with more than 2,000 values is left to a schedule.
- **On a schedule:** an admin creates a schedule of repositories and orgs,
  every so many days. Each run opens one pull request per repository with
  every value it moved, from the default branch's head, and skips a
  repository while an earlier run's pull request is still open there.
  "Run now" starts one at once.

Watch them on the reseal pages, or with the admin token:

- **Runs** (`.../admin/reseal/runs`, then `.../runs/{id}`): each
  repository's status, its pull request, and the values that failed, with
  why: "no key in this cluster opens it" for a value no key of the agent's
  cluster opens with its label (sealed for another env, or with a key
  deleted from the cluster), "no agent answered in time" for a command
  that expired, "the key it was resealed onto was revoked" for a value
  left out of its pull request, and so on. A run reads at most 200 files
  of a repository and covers at most 500 repositories; it says so when it
  left any out. A run that makes no progress for an hour fails, so its
  schedule can run again.
- **Reseal pull requests** (`.../admin/reseal/pull-requests`): every open
  one, and with `?state=all` the merged and closed ones of the last 180
  days. Ticks check open ones on GitHub about every 15 ticks; a run checks
  one again before it skips a repository for it.

Once the pull requests are merged and deployed, the old keys' references
fall to zero on the fleet page, and they can be revoked and deleted.

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

**A seal is refused with "no usable sealing key", or the env says a new
key is needed.** Every key the clusters share is revoked or dated in the
future (`no_usable_key` in the fleet). Let a controller renew its key, or
reinstate a key revoked by mistake.

**An agent's issues say "key order unknown".** The agent cannot tell how
its controller orders keys: the setting comes from somewhere it cannot
read, such as a ConfigMap through `envFrom`, or the controller's
Deployment could not be read. It refuses to restore keys, so the control
plane sends it none, and its cluster cannot catch up on keys the others
hold. Set the key order where the agent can read it: the controller's
arguments, or a plain environment variable.

**A key cannot be deleted.** The fleet page's reason (`delete_blocked`)
says which: values still sealed with it, named by cluster; values a
cluster without the key cannot decrypt, which may be sealed with it; no
escrowed copy, so the deletion could not be undone (reinstate the key, let
a cluster escrow it, and revoke it again); a cluster whose agent lacks
`cleanup`, in its values or its registry entry; a count that failed, whose
error is in the agent's issues and `key.count_failed` (often RBAC: its
chart predates `cleanup`, or the SealedSecrets CRD is missing; or a count
too large for one go, which the next counts go on with); or a count that
predates the revocation or is over an hour old, which the next count
fixes. An agent refuses a removal when a value is
sealed with the key by its own count (`key.remove_refused`), and is asked
again 10 minutes later.

**An agent's issues say values "match none of its keys".** Its controller
cannot decrypt those values: they were sealed with a key the cluster does
not hold, such as a key deleted from it, or for another env or cluster. A
deleted key within its 30 days can be reinstated.

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

**Pages answer "GitHub is limiting the sealer's requests for now; try
again in …" (503), or the repository list says it is incomplete.** The
GitHub App's installation has used its hourly request budget, which every
env and user share, or a list ran out of time checking permissions. The
control plane logs `github.rate_limited`, and `github.rate_limit_low` once
the budget falls below a tenth. Nothing retries; requests work again when
the budget resets. An incomplete list fills in on the next load, from what
was checked.

**The repository list or a file listing answers "this request must come
from the sealer's own pages" (403).** These calls cost GitHub requests,
so they are refused unless the browser says the UI's own page sent them
(`Sec-Fetch-Site: same-origin`) or the UI's `X-Requested-With` header is
there. A proxy in front of the control plane, such as CloudFront with an
origin request policy that lists headers, must pass at least one of them
on.

**A person is told they "may not use the prod env".** Their session does
not grant it. Teams are checked at sign-in, so after joining a team they
sign out and in again.

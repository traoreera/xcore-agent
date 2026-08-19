# xcore-agent

Deployment agent that takes a project from a Hub-hosted artifact to a running
set of plugins on a client's VPS, without ever needing `git` or shell access
on the target host. Two Hubs, two pipelines:

- **`deploy` / `pipeline.py`** — the originally-designed `.xdeploy` artifact:
  encrypted, Ed25519-signed, multi-plugin-per-project, fetched from a richer
  "XCore Hub" that doesn't exist yet (see "XCore Hub API contract" below —
  still a *proposed*, unvalidated contract).
- **`deploy-marketplace` / `marketplace_pipeline.py`** — the **real**,
  already-running `xcore-team/marketplace` backend: plain HMAC-signed ZIPs,
  one plugin (or extension) per deployment, `X-API-Key` auth. See "The real
  xcore-team/marketplace API contract" below — this one is validated against
  the actual backend source, not inferred.

```
# .xdeploy (proposed Hub)
authenticate -> request_artifact -> download -> verify_signature ->
obtain_key -> decrypt -> extract -> verify_manifest -> validate_project ->
resolve_plugins -> resolve_sequence -> install -> healthcheck -> notify

# marketplace (real Hub)
fetch -> verify_signature (HMAC) -> extract -> load_plan (local file) ->
resolve_sequence -> install -> healthcheck
```

Each stage is enforced by an explicit state machine (`agent/state.py` and
`agent/marketplace_state.py` respectively) so neither pipeline can skip a
security-relevant step — e.g. it is structurally impossible to reach
`install` without a stage having verified the artifact's signature first.

On top of the `.xdeploy` pipeline, `Watcher` (`agent/watcher.py`) is the
CI/CD loop: poll a project's latest version/tag and redeploy automatically
when it changes, then run garbage collection so rollback snapshots and
cached downloads don't grow forever. `MarketplaceWatcher`
(`agent/marketplace_watcher.py`) is the same loop for the marketplace flow,
polling one plugin/extension slug via `MarketplaceClient.get_latest_version`
and redeploying through `MarketplaceDeploymentRunner`.

## What's real vs. stubbed today

| Component | Status |
|---|---|
| `install.yaml` / `manifest.json` schema (Pydantic, closed action enum) | Implemented, tested |
| `.xdeploy` packer (tar/zstd/AES-256-GCM/Ed25519) | Implemented, tested — `xcore_agent/packer/` |
| Ed25519 signature verification, AES-256-GCM decryption, zstd decompression | Implemented, tested |
| Tar extraction with path-traversal guarding | Implemented, tested |
| Content-hash re-verification post-extraction | Implemented, tested |
| Filesystem install / snapshot / rollback driver | Implemented, tested |
| CI/CD watch loop (`Watcher`: poll Hub, redeploy on version change) | Implemented, tested — `agent/watcher.py` |
| Garbage collector (stale snapshots + cached versions, forced restart) | Implemented, tested — `agent/gc.py` |
| `SystemdSupervisor` / `DockerSupervisor` / `KubernetesSupervisor` (real start/stop/restart/healthcheck) | Implemented, tested — `agent/systemd_supervisor.py`, `agent/docker_supervisor.py`, `agent/kubernetes_supervisor.py` |
| Provisioner registry (`provision` action) + `ShellCommandProvisioner` | Implemented, tested — see "Provisioning backing services" below |
| Required environment variable validation (`write_env`) | Implemented, tested — from an optional `environment:` block in `plugin.yaml` |
| CI (GitHub Actions: black/isort/flake8/mypy/pytest) | Implemented — `.github/workflows/ci.yml` |
| `HttpHubClient` (auth, latest-version, artifact request, DEK unwrap, notify) | Implemented, tested against a **proposed** REST contract — see "XCore Hub API contract" below. This hypothetical richer Hub still doesn't exist; a real one does now, and it's a *different* contract (see next row) |
| `MarketplaceClient` / `MarketplaceDeploymentRunner` (`X-API-Key` auth, HMAC-signed ZIP fetch, extract, local install plan, install, deployment-status reporting) | Implemented, tested against the **real, validated** `xcore-team/marketplace` API contract — `agent/marketplace_client.py`, `agent/marketplace_pipeline.py`. See "The real xcore-team/marketplace API contract" below |
| Plugin resolution from a git repo (`PluginSource` — marketplace/registry links) | Implemented, tested against real local git repos — `plugin_resolver.py`, public and private (HTTPS token or SSH) |
| k8s supervisor (`KubernetesSupervisor`: scale/rollout-restart/rollout-status via `kubectl`, one Deployment per plugin) | Implemented, tested — `agent/kubernetes_supervisor.py`, `--supervisor kubernetes` on `watch`/`watch-marketplace`/`gc` |
| CI/CD watch loop for the marketplace flow (`MarketplaceWatcher`: poll one slug, redeploy on version change, GC + restart) | Implemented, tested — `agent/marketplace_watcher.py`, exposed as `watch-marketplace` |
| `install.yaml` scaffolding (`scaffold_install_plan`: prepare/install_plugin/write_env/start/healthcheck) | Implemented, tested — `scaffold.py`, exposed as `init-plan` |

`install.yaml` has **no generic "run a command" action** — every step is one
of a fixed, closed set (`prepare`, `provision`, `install_plugin`,
`configure_plugin`, `write_env`, `start`, `stop`, `restart`, `healthcheck`,
`rollback`, ...), validated by a discriminated Pydantic union before the
agent executes anything. A tampered or malicious artifact cannot turn
xcore-agent into an arbitrary remote-execution primitive.

## Layout

```
xcore_agent/
├── schema/
│   ├── install.py          # install.yaml — steps, action whitelist, dependency graph
│   └── manifest.py         # manifest.json — project/plugin metadata + content hash
├── packer/
│   └── builder.py          # build_artifact() — tar/zstd/encrypt/sign a project into .xdeploy
├── agent/
│   ├── state.py             # DeploymentState + allowed transitions
│   ├── errors.py
│   ├── hub_client.py        # HubClient protocol + HttpHubClient (proposed REST contract)
│   ├── install_driver.py    # filesystem install/snapshot/rollback + Supervisor/Provisioner protocols
│   ├── systemd_supervisor.py # Supervisor backed by `systemctl`
│   ├── docker_supervisor.py # Supervisor backed by the `docker` CLI
│   ├── kubernetes_supervisor.py # Supervisor backed by the `kubectl` CLI (Deployments)
│   ├── pipeline.py          # DeploymentRunner — one deployment, start to finish
│   ├── watcher.py           # Watcher — CI/CD loop: poll Hub, redeploy on version change
│   ├── gc.py                # GarbageCollector — prune snapshots/cache, force plugin restarts
│   ├── provisioners.py      # ShellCommandProvisioner + config loader for 'provision'
│   └── state_store.py       # tracks which version is currently installed
├── plugin_resolver.py        # PluginResolver — fetches a PluginSource plugin from git
├── crypto.py                 # signature verification, AES-GCM, content digest
├── scaffold.py                # scaffold_install_plan() — generates a starter install.yaml
└── cli.py                    # validate / init-plan / build / deploy / watch / gc
```

## Usage

```bash
poetry install

# Validate an install.yaml (and optionally manifest.json) — no network needed.
poetry run xcore-agent validate deployment/install.yaml --manifest-json manifest.json

# Scaffold a starter install.yaml: prepare -> install_plugin per --plugin ->
# optional write_env -> start -> healthcheck. Validated before it's written.
poetry run xcore-agent init-plan my-plugin \
  --plugin demo --env-template demo=plugins/demo/.env.template \
  --output deployment/install.yaml

# Build a signed, encrypted .xdeploy artifact from a project source tree.
poetry run xcore-agent build ./my-project \
  --project-id prj_... --project-name my-erp --version 1.0.0 \
  --output ./my-erp-1.0.0.xdeploy.enc

# One-shot deploy — requires a live XCore Hub, not available yet.
poetry run xcore-agent deploy \
  --project-id prj_... --version 1.0.0 \
  --xdevkey xdev_... --deployment-credential xdpk_... \
  --project-root /etc/xcore/projects/my-erp \
  --signer-public-key ./hub_signing.pub

# CI/CD loop: watch Hub for new versions and redeploy automatically.
poetry run xcore-agent watch \
  --project-id prj_... --xdevkey xdev_... --deployment-credential xdpk_... \
  --project-root /etc/xcore/projects/my-erp \
  --signer-public-key ./hub_signing.pub \
  --interval 60 --supervisor systemd

# Manual garbage collection + forced plugin restart.
poetry run xcore-agent gc \
  --project-root /etc/xcore/projects/my-erp \
  --cache-root ~/.cache/xcore-agent/prj_... \
  --keep-version 1.0.0 --force-restart --supervisor docker

# Same, but plugins run as Kubernetes Deployments (one per plugin,
# named xcore-plugin-<id> by default) instead of systemd units/containers.
poetry run xcore-agent gc \
  --project-root /etc/xcore/projects/my-erp \
  --cache-root ~/.cache/xcore-agent/prj_... \
  --keep-version 1.0.0 --force-restart --supervisor kubernetes \
  --k8s-namespace my-erp --k8s-context prod-cluster

# Deploy a single plugin from the REAL xcore-team/marketplace.
# install.yaml is supplied locally — the marketplace ships plain plugin
# source, not a deployment plan (see the contract section below).
poetry run xcore-agent deploy-marketplace my-plugin \
  --version latest --kind plugin \
  --api-key xdk_... --signing-secret <the-developer's-hmac-secret> \
  --hub-url https://marketplace.example.com/app/marketplace \
  --project-root /etc/xcore/projects/my-erp \
  --install-plan ./deployment/install.yaml

# CI/CD loop for the marketplace flow: poll one slug and redeploy on version change.
poetry run xcore-agent watch-marketplace my-plugin \
  --kind plugin \
  --api-key xdk_... --signing-secret <the-developer's-hmac-secret> \
  --hub-url https://marketplace.example.com/app/marketplace \
  --project-root /etc/xcore/projects/my-erp \
  --install-plan ./deployment/install.yaml \
  --interval 60 --supervisor systemd
```

## Tests

```bash
poetry install --with dev
poetry run pytest -v
```

`tests/test_pipeline.py` and `tests/test_watcher.py` run the full `.xdeploy`
pipeline and CI/CD loop end-to-end (build via the real packer, sign, encrypt,
download via a fake Hub, verify, decrypt, decompress, extract, install,
persist state, garbage-collect, roll back on failure) without any network
access — the fakes stand in only for XCore Hub, which has no real API yet.

`tests/test_marketplace_client.py` and `tests/test_marketplace_pipeline.py`
do the same for the real-Marketplace flow: a real GitHub-zipball-shaped ZIP,
real HMAC-SHA256 signing/verification, real extraction (including the
single-top-level-directory flattening GitHub's zipball API requires) and
path-traversal guarding, real install.yaml dispatch and rollback — only the
HTTP transport is faked (`httpx.MockTransport`), same as `test_http_hub_client.py`.

## XCore Hub API contract (proposed, not validated)

XCore Hub doesn't exist yet, so `HttpHubClient` is implemented against a
REST contract *inferred* from this project's architecture notes rather than
a published spec. It's a concrete, working starting point — build the real
Hub against these routes, or edit `hub_client.py` once the real ones are
decided. Nothing else in xcore-agent needs to change either way: the
pipeline, watcher, and CLI all depend on the `HubClient` protocol, not on
this implementation.

All bodies are JSON; binary fields (`signature`, `signer_public_key`, `dek`,
`artifact_signature`) are base64; auth is `Authorization: Bearer <access_token>`
except on `/v1/auth` itself.

```
POST /v1/auth
    -> {xdevkey, project_id}
    <- {access_token}

GET /v1/projects/{project_id}/versions/latest
    <- {version}

GET /v1/projects/{project_id}/artifacts/{version}
    <- {download_url, signature, signer_public_key}

GET <download_url>                    (may be a different host — e.g. signed
    <- raw bytes                        blob storage — not necessarily the Hub)

POST /v1/deployments/authorize
    -> {deployment_credential, artifact_signature}
    <- {dek}                            (access revocation is enforced here)

POST /v1/deployments/report
    -> {project_id, deployment_id, status, version, started_at,
        completed_at, plugins}
    <- {deployment_id}
```

A 401/403 from `/v1/auth` or `/v1/deployments/authorize` raises
`AuthenticationError`; any other non-2xx raises `ArtifactError` (or
`DeploymentError` for `/v1/auth` and `/v1/deployments/report`) with the
status code and the response's `error` field, if present, in the message.
`tests/test_http_hub_client.py` exercises all of this against
`httpx.MockTransport` — no network, no real Hub needed to verify the client
speaks its own contract correctly.

## The real xcore-team/marketplace API contract (validated)

Unlike the section above, this one is not inferred — it's read directly from
the `xcore-team/marketplace` backend source (`app/marketplace`, `app/xdevkeys`).
It is a **structurally different** contract, not just a different base URL,
which is why it gets its own client (`marketplace_client.py`) and pipeline
(`marketplace_pipeline.py`) instead of a second `HubClient` implementation:

| | Proposed `.xdeploy` Hub | Real xcore-team/marketplace |
|---|---|---|
| Auth | Login exchange → bearer token | Static `X-API-Key: xdk_...` header on every request |
| Unit of deployment | A "project" — many plugins, one manifest | One plugin *or* one extension ("service"), by marketplace slug |
| Artifact format | Encrypted (`.xdeploy`): tar → zstd → AES-256-GCM | Plain ZIP (GitHub's zipball API, unmodified) |
| Integrity/authenticity | Ed25519 signature over the ciphertext, verified against a distributed public key | `X-Signature: hmac_sha256:<hex>` over the ZIP bytes, verified against a **shared secret** |
| Deployment orchestration (`install.yaml`) | Bundled inside the artifact | **Not present in the artifact at all** — supplied locally by the operator (see below) |
| Deployment reporting | `POST /v1/deployments/report` | `POST /deployments/report` (`app/xdeployments`) — `X-API-Key` auth, best-effort, alongside the always-written local JSON report |

**Auth**: `X-API-Key: xdk_...` (obtained via `POST /xdevkeys/api-keys` on the
marketplace), sent on the one call that needs it (`fetch_artifact`).
`get_latest_version` reads the public plugin/service detail route, no key needed.

```
GET /plugins/{slug}                         (or /services/{slug} for an extension)
    <- {..., "latest_version": "1.2.3", ...}

GET /plugins/{slug}/install?version=latest  (or /services/{slug}/install)
    Header: X-API-Key: xdk_...
    <- raw ZIP bytes
       Header: X-Signature: hmac_sha256:<hex>
       Header: X-Plugin: name@version        (X-Service for an extension)
       Header: X-Repo: owner/repo@tag
```

**The HMAC signature is symmetric — read this before trusting it.** Unlike
Ed25519, whoever holds the signing secret can also *forge* a signature with
it, and the secret here is the plugin developer's own `xdevkeys` signing
secret — not a key the Marketplace publishes for third parties to verify
against. `MarketplaceDeploymentRunner` still checks it (it catches transport
corruption and accidental tampering, and the operator must have obtained the
secret from the developer to check it at all), but treat that check as
"this is the bytes the developer's key produced," not as a substitute for
trusting the Marketplace connection itself (TLS + your own API key) the way
the `.xdeploy` design's Ed25519 verification was meant to let you skip
trusting the transport. `--signing-secret` is deliberately a required CLI
argument, not something xcore-agent fetches on your behalf, so this
trust decision stays visible at the call site.

**Deployment orchestration is not in the artifact.** A plain GitHub zipball
has no `manifest.json` or `deployment/install.yaml` — it's just the
developer's repository. `deploy-marketplace --install-plan` therefore points
at a file on the *operator's own host*, exactly the same trust boundary
`--provisioners-config` already uses (see "Provisioning backing services"
below): the artifact fetched from the Hub supplies code, never deployment
instructions. `MarketplaceDeploymentRunner` still validates that
`install_plan.project_id == slug` as a sanity check, but the plan's actual
steps are never trusted input — they're a local file the operator wrote.

**Deployment status reporting.** Every `deploy-marketplace` run — success,
failure, or rollback — calls `POST /deployments/report` (`X-API-Key` auth)
after writing its local JSON report, so the Marketplace can show which
version is actually running where (`GET /deployments/{kind}/{slug}/hosts` —
a "fleet" view keyed by `--host-id`, which defaults to this machine's
hostname if not given). This is intentionally **best-effort**:
`MarketplaceClient.report_deployment` can raise, but
`MarketplaceDeploymentRunner` catches that itself and only logs a warning —
a Hub that's down or a key that's expired must never turn an otherwise-
successful (or otherwise-already-failed) deployment into a different
outcome. A deployment report is scoped to whoever's API key made the call,
not to the plugin's publisher — you don't need to own a plugin to deploy it
and track your own rollout of it.

`tests/test_marketplace_client.py` and `tests/test_marketplace_pipeline.py`
exercise all of this end-to-end against `httpx.MockTransport`.

## Embedded vs. registry-resolved plugins

A plugin in `install.yaml`/`manifest.json` is either:

- **Embedded** — its full code sits inside `plugins/<id>/` in the artifact,
  tarred/encrypted with everything else. `PluginRef.sha256` is required and
  is the hash the agent re-verifies post-extraction. This is the default —
  simplest, self-contained, no extra network calls at deploy time.

- **Source-based** — `plugin.yaml` declares a `source: {url, ref,
  subdirectory}` block (typically handed out by a marketplace/registry as a
  resolvable link). Only non-code metadata (`plugin.yaml`, `.env.template`)
  ships in the artifact; the actual code is fetched from `url` at `ref` via
  `git` during the pipeline's `resolve_plugins` stage, merged onto that
  metadata. `PluginRef.sha256` is optional here — the packer doesn't fetch
  external repos at build time, so it has nothing to hash unless pinned out
  of band. **Use a commit SHA for `ref`, not a branch or tag**: only a SHA
  is content-addressed, so it's the only form that makes a pinned `sha256`
  (or the absence of one) mean something — a mutable branch can change
  without the manifest ever noticing.

`PluginResolver` (`plugin_resolver.py`) fetches via `git init` + `fetch
--depth 1 <ref>` + `checkout FETCH_HEAD`, which works for a branch, tag, or
commit SHA alike (unlike `git clone --branch`, which can't target an
arbitrary commit). Public and private repos are the same operation with
different auth, exactly like using `git` from a shell:

- **SSH** (`git@host:org/repo.git`) — authenticates via the host's own SSH
  agent/config; xcore-agent does nothing special.
- **HTTPS** — authenticates via a per-host token from `--git-token
  HOST=TOKEN` (repeatable, on `deploy`/`watch`), spliced into the URL as
  `https://x-access-token:<token>@host/...`. No token configured for that
  host just means the URL is used as-is (fine for a public repo).

## Provisioning backing services (`provision` action)

A plugin can declare a `provision` step in `install.yaml` for setting up a
backing service it needs — a database, a message queue, whatever. xcore-agent
deliberately ships **no** database/queue client to support this: a lean
deployment agent shouldn't carry backend-specific dependencies most projects
don't need. Instead, `provision` runs an **operator-configured shell
command**:

```yaml
# provisioners.yaml, passed via --provisioners-config on deploy/watch
demo:
  command: ["/usr/local/bin/provision-demo-schema.sh"]
  env:
    PGHOST: localhost
  timeout: 120   # seconds, default 300
```

The plugin id is appended as the command's last argument and exported as
`PROVISION_PLUGIN_ID`. This is safe to shell out to — unlike anything inside
`install.yaml` itself — because the command comes from the *operator's own
trusted host-side config*, never from the (untrusted) `.xdeploy` artifact,
which only ever supplies a plugin id via `ProvisionStep`. The operator
already has root on their own VPS; nothing here hands the artifact a new
capability. No config passed to `provision` for a plugin that has one → a
clear `InstallError`, not a silent no-op.

## Key custody model

xcore-agent never generates or stores long-lived secrets. The artifact's
per-version data-encryption key (DEK) is obtained at deploy time from XCore
Hub and kept only in memory for the duration of one deployment. XDevKey
authenticates the *project*; a separate deployment credential authorizes
*this deployment* to have the DEK unwrapped — the two are deliberately not
the same secret, so a leaked XDevKey does not, by itself, grant artifact
decryption.

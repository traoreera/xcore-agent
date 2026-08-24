# CLI reference

`xcore-agent` is a Typer application. Run `xcore-agent --help` for the full
list, or `xcore-agent <command> --help` for a command's options. Long-lived
credentials can be passed via environment variables (see
[Getting started](getting-started.md#environment-variables)) so they never
appear in the process list.

## Global options

| Option | Description |
|---|---|
| `--help` | Show help and exit |
| `--version` | Show the version and exit |

## `validate`

Validate an `install.yaml` (and optionally a `manifest.json`) — local only,
no network needed.

```
xcore-agent validate <install-yaml> [--manifest-json <path>]
```

| Argument / option | Description |
|---|---|
| `install-yaml` | Path to `install.yaml` |
| `--manifest-json` | Optional path to `manifest.json` to validate alongside it |

Output prints the step count and the resolved execution order.

## `init-plan`

Generate a starter `install.yaml` for a project. The result is validated
through `InstallPlan` before being written, so it is guaranteed loadable as-is.

```
xcore-agent init-plan <project-id> --plugin <id> [options]
```

| Argument / option | Description |
|---|---|
| `project-id` | `project_id` stamped in the plan — must equal the plugin's marketplace slug for `deploy-marketplace`/`watch-marketplace` |
| `--plugin` | Plugin id to install (repeatable) — one `install_plugin` step per id, in order given |
| `--extension` | Extension id to install (repeatable) — one `install_extension` step per id, separate namespace from `--plugin` |
| `--version` | Version to stamp in the plan (default `0.1.0`) |
| `--output` | Where to write the generated `install.yaml` (default `deployment/install.yaml`) |
| `--env-template` | `PLUGIN=RELATIVE_PATH` adding a `write_env` step (repeatable) |
| `--snapshot` | Take a rollback snapshot before each install step (default on) |
| `--healthcheck` | Append a `healthcheck` step after `start` (default on) |
| `--healthcheck-timeout` | Healthcheck timeout, e.g. `30s` or `2m` (default `30s`) |
| `--healthcheck-retries` | Healthcheck retry count (default 3) |
| `--force` | Overwrite `--output` if it already exists |

See [init-plan scaffolding](scaffold.md) for the generated plan shape.

## `build`

Build, encrypt, and sign a `.xdeploy` artifact from a project source tree.

```
xcore-agent build <source-root> --project-id <id> --project-name <name>
                 --version <ver> --output <path> [--signing-key-file <path>]
```

| Argument / option | Description |
|---|---|
| `source-root` | Project source tree: `plugins/`, `integration.yaml`, `deployment/install.yaml` |
| `--project-id` | Project id (`prj_...`) |
| `--project-name` | Project display name |
| `--version` | Version to stamp, e.g. `1.0.0` |
| `--output` | Output path for the encrypted `.xdeploy` artifact |
| `--signing-key-file` | Raw 32-byte Ed25519 private key. A throwaway key is generated (and **not** saved) if omitted |

The DEK (hex) and signer public key (hex) are printed to stdout — hand the
DEK to the Hub for storage and distribute the public key to agents. They are
never saved by the agent.

## `deploy`

Deploy a project version fetched from XCore Hub (the proposed `.xdeploy`
contract). Requires a live Hub API — currently fails at the `authenticate`
step by design, until the real Hub exists.

```
xcore-agent deploy --project-id <id> --version <ver>
        --xdevkey <key> --deployment-credential <cred>
        --project-root <path> --signer-public-key <path>
        [--hub-url <url>] [--git-token HOST=TOKEN]...
        [--provisioners-config <path>] [--plugin-secret-key <key>]
```

| Option | Environment | Description |
|---|---|---|
| `--project-id` | `XCORE_PROJECT_ID` | Project id (`prj_...`) |
| `--version` | | Version to deploy, e.g. `1.0.0` |
| `--xdevkey` | `XCORE_XDEVKEY` | Project XDevKey |
| `--deployment-credential` | `XCORE_DEPLOYMENT_KEY` | Deployment credential (authorizes DEK unwrap) |
| `--hub-url` | `XCORE_HUB_URL` | Hub base URL (default `https://hub.xcorehub.dev`) |
| `--project-root` | | Target install directory, e.g. `/etc/xcore/projects/my-erp` |
| `--signer-public-key` | | Path to the Hub's Ed25519 public key (raw 32 bytes) |
| `--git-token` | | `HOST=TOKEN` for a private git host a source-based plugin needs (repeatable) |
| `--provisioners-config` | | YAML mapping plugin id → `{command, env, timeout}` for the `provision` action |
| `--plugin-secret-key` | `XCORE_PLUGIN_SECRET` | Host's own `plugins.secret_key` — signs `execution_mode: trusted` plugins so this host's strict_trusted check can load them |

## `deploy-marketplace`

Deploy a single plugin or extension fetched from the real
`xcore-team/marketplace` backend — `X-API-Key` auth, HMAC-SHA256-signed plain
ZIP.

```
xcore-agent deploy-marketplace <slug> [--version latest] [--kind plugin|service]
        --api-key <key> --signing-secret <secret>
        --project-root <path> --install-plan <path>
        [--hub-url <url>] [--host-id <id>]
        [--provisioners-config <path>] [--plugin-secret-key <key>]
```

| Option | Environment | Description |
|---|---|---|
| `slug` | | Plugin or extension slug on the marketplace |
| `--version` | | Version to deploy, or `latest` (default `latest`) |
| `--kind` | | `plugin` (default) or `service` |
| `--api-key` | `XCORE_API_KEY` | `xdevkeys` API key (`xdk_...`) |
| `--signing-secret` | `XCORE_SIGNING_SECRET` | The publisher's HMAC signing secret — obtained out-of-band. See the trust-model caveat in [The real marketplace flow](marketplace.md) |
| `--hub-url` | `XCORE_HUB_URL` | Hub root **without** a plugin segment (default `https://marketplace.xcore.dev`) |
| `--project-root` | | Target install directory |
| `--host-id` | `XCORE_HOST_ID` | Host identifier reported with deployment status; defaults to hostname |
| `--install-plan` | | **Local** `install.yaml` — supplied by the operator, never fetched from the Hub |
| `--provisioners-config` | | YAML mapping plugin id → `{command, env, timeout}` for `provision` |
| `--plugin-secret-key` | `XCORE_PLUGIN_SECRET` | Same as `deploy --plugin-secret-key`; no effect for `kind=service` |

## `watch-marketplace`

The CI/CD loop for the marketplace flow — poll one slug and redeploy on
version change, then run garbage collection.

```
xcore-agent watch-marketplace <slug> [--kind plugin|service]
        --api-key <key> --signing-secret <secret>
        --project-root <path> --install-plan <path>
        [--interval 60] [--once] [--keep-snapshots 3]
        [--supervisor none|systemd|docker|kubernetes]
        [--systemd-user-scope] [--k8s-namespace <ns>] [--k8s-kubeconfig <path>] [--k8s-context <ctx>]
        [--provisioners-config <path>]
```

| Option | Environment | Description |
|---|---|---|
| `slug` | | Plugin or extension slug on the marketplace |
| `--kind` | | `plugin` (default) or `service` |
| `--api-key` | `XCORE_API_KEY` | `xdevkeys` API key (`xdk_...`) |
| `--signing-secret` | `XCORE_SIGNING_SECRET` | Publisher HMAC signing secret |
| `--hub-url` | `XCORE_HUB_URL` | Hub root (default `https://marketplace.xcore.dev`) |
| `--project-root` | | Target install directory |
| `--host-id` | `XCORE_HOST_ID` | Host identifier; defaults to hostname |
| `--install-plan` | | **Local** `install.yaml`, supplied by the operator |
| `--interval` | | Seconds between marketplace checks (default 60) |
| `--once` | | Check once and exit instead of looping forever |
| `--keep-snapshots` | | Rollback snapshots to keep for this plugin (default 3) |
| `--supervisor` | | How to restart the plugin after a redeploy and GC pass (`none`, `systemd`, `docker`, `kubernetes`) |
| `--systemd-user-scope` | | Use `systemctl --user` vs system-wide (default on) |
| `--k8s-namespace` | | Namespace for `--supervisor kubernetes` (default `default`) |
| `--k8s-kubeconfig` | | Path to a kubeconfig (defaults to kubectl's own) |
| `--k8s-context` | | kubeconfig context (defaults to kubectl's current) |
| `--provisioners-config` | | YAML mapping plugin id → `{command, env, timeout}` for `provision` |

## `watch`

The CI/CD loop for the `.xdeploy` flow — poll XCore Hub for a new
version/tag and redeploy automatically. Runs garbage collection after every
successful redeploy. Requires a live Hub API (not yet available).

```
xcore-agent watch --project-id <id> --xdevkey <key> --deployment-credential <cred>
        --project-root <path> --signer-public-key <path>
        [--interval 60] [--once] [--keep-snapshots 3]
        [--supervisor none|systemd|docker|kubernetes]
        [--systemd-user-scope] [--k8s-namespace <ns>] [--k8s-kubeconfig <path>] [--k8s-context <ctx>]
        [--git-token HOST=TOKEN]... [--provisioners-config <path>]
```

Options match `deploy` plus the loop controls from `watch-marketplace`
(`--interval`, `--once`, `--keep-snapshots`, supervisor flags).

## `gc`

Purge stale rollback snapshots and cached artifact downloads; optionally
force every installed plugin to restart afterward.

```
xcore-agent gc --project-root <path> [--cache-root <path>]
        [--keep-version <ver>]... [--keep-snapshots 3]
        [--force-restart] [--supervisor systemd|docker|kubernetes]
        [--systemd-user-scope] [--k8s-namespace <ns>] [--k8s-kubeconfig <path>] [--k8s-context <ctx>]
```

| Option | Description |
|---|---|
| `--project-root` | Project root (extracted layout) |
| `--cache-root` | Cache root to prune (e.g. `~/.cache/xcore-agent/<project-id>`) |
| `--keep-version` | Version(s) to keep in the cache (repeatable) |
| `--keep-snapshots` | Rollback snapshots to keep per plugin (default 3) |
| `--force-restart` | Restart every installed plugin after cleanup |
| `--supervisor` | Which supervisor to use when `--force-restart` is set (default `systemd`) |
| `--systemd-user-scope` | Use `systemctl --user` vs system-wide (default on) |
| `--k8s-namespace` / `--k8s-kubeconfig` / `--k8s-context` | Kubernetes supervisor settings |
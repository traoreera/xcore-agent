# Supervisors

The three `Supervisor` implementations that start/stop/restart/healthcheck
plugins, plus the shared protocol.

## Protocol & `NullSupervisor`

::: xcore_agent.agent.install_driver.Supervisor
::: xcore_agent.agent.install_driver.NullSupervisor

## `SystemdSupervisor`

Backed by `systemctl` (optionally `systemctl --user`).

::: xcore_agent.agent.systemd_supervisor

## `DockerSupervisor`

Backed by the `docker` CLI.

::: xcore_agent.agent.docker_supervisor

## `KubernetesSupervisor`

Backed by the `kubectl` CLI — scale/rollout-restart/rollout-status, one
Deployment per plugin (`xcore-plugin-<id>` by default).

::: xcore_agent.agent.kubernetes_supervisor
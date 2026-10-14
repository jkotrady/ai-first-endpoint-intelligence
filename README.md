# AI-first Endpoint Intelligence

Development source snapshot of an MSP/MSSP forensic collection platform.
Windows XP/7 and selected Windows10/LTSC/11 editions remain required targets.
This local pilot is not a production release or complete compatibility claim.

## Auditable native collectors

- `collectors/windows/`: separate C sources for F01 identity, F04 processes,
  F08 IPv4 TCP/PID and F15 read-only Windows service inventory.
- `collectors/catalog.json`: explicit allowlist and implementation limitations.
- `agent/windows/agent.c`: visible foreground agent, outbound TLS polling,
  version-pinned jobs and result upload; no arbitrary remote shell.
- `agent/windows/collector_main.c`: experimental standalone wrapper with exactly
  one compile-time collector entrypoint per EXE.

The active agent still executes built-in collectors. Independently downloadable
EXEs are an offline experiment. Signed manifests, worker isolation, revocation
and controlled rollout are required before downloaded-code execution is enabled.

Sources belong in this repository, not customer GUI downloads. Build manifests
link source hashes to executables. Same-host repeat builds are checked;
independent rebuild and signed releases remain pending. Source publication is
not remote attestation of an already compromised endpoint.

Read the [package design](docs/COLLECTOR-PACKAGES.md),
[authoring workflow](docs/COLLECTOR-AUTHORING.md), and
[audit guide](docs/AGENT-AUDIT.md).

## Local builds — Ubuntu amd64

```sh
python3 scripts/bootstrap-agent.py
sh scripts/build-agent.sh
python3 scripts/build-collectors.py
```

Pinned dependencies are extracted under ignored `work/`, without global
installation. Exact Ubuntu package versions must remain available in your
configured repositories. Outputs are unsigned. Windows media/licenses are not
included.

For the web/API pilot:

```sh
python3 scripts/bootstrap.py
sh scripts/check.sh
work/bin/forensics-console --init operator --state work/pilot
work/bin/forensics-console --state work/pilot
```

Initialize only a new state directory. Credentials and TOTP setup secret are
created locally with owner-only permissions. Open `http://127.0.0.1:8080/setup`
for authenticator instructions. The console/TLS gateway bind only to loopback.
This snapshot is not a public hosting recipe.

## Security and AI status

Password+TOTP sessions, customer grants and device tokens protect the pilot.
Manual and AI flows share typed collectors and version-pinned human approval.
The OpenAI adapter uses the user's API key and explicit data-sharing consent;
live provider testing remains pending. Direct ChatGPT MCP is not implemented.

A separate local Keycloak lab prepares OIDC; it is not connected to application
login yet. Production RBAC/recovery, full resource governor, 50 collectors,
payments and E2EE are unfinished.

[Development notes](docs/DEVELOPMENT.md) and
[Windows10/11 lab preparation](docs/WINDOWS10-11-LAB.md) document these limits.
Private lab evidence and internal handoffs referenced there are intentionally
absent from this source snapshot.

Project licensing terms have not yet been selected. Third-party notices are in
`agent/windows/licenses/`.

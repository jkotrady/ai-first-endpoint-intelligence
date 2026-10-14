See [web, registration, 2FA and AI guide](PILOT-WEB-AI.md) for pilot 0.2 routes and provider boundaries.

# Local pilot development (T061)

Default executable mode now runs the persistent pilot in internal/pilot. The historical T011 description below applies only to --demo; it does not describe the default application.

## Startup and access

Run scripts/check.sh, then initialize a NEW state path with `work/bin/forensics-console --init operator --state work/pilot`. Initialization refuses an existing directory. Credentials and TOTP secret are written to work/pilot/first-login.txt with mode 0600; read locally and enroll the secret in an authenticator. Run `work/bin/forensics-console --state work/pilot` from the project root. UI: http://127.0.0.1:8080. Agent TLS: 127.0.0.1:8443. Ctrl+C stops cleanly. Never expose these pilot listeners publicly.

Existing state: skip --init. Persistent state and local CA/server certificates live in work/pilot (0700). Back up the entire private directory only while the server is stopped. Login sessions are memory-only and expire on restart; data and replay counters persist. Preserve private permissions. There is no password/TOTP recovery UI yet. A failed interrupted `.tmp` write may require owner inspection before restart; never silently overwrite state. Certificates currently require reprovisioning when they expire.

## Native build

`scripts/build-agent.sh` uses extracted Ubuntu MinGW i686 GCC 13.2 and Mbed TLS 3.6.7 in work/toolchains; it does not install packages globally. Exact package/release hashes are in outputs/pilot-toolchain-2026-10-13.json. Run `python3 scripts/bootstrap-agent.py` on Ubuntu amd64 (Python 3.12+, apt-get download and dpkg-deb required); exact versions must be available in configured repositories or already cached. It fails on a missing version or checksum mismatch. Output: work/bin/forensics-agent-x86.exe and agent-imports.txt. XP subsystem 5.1, static C runtime helpers; no PowerShell dependency. Mbed TLS uses Windows CryptGenRandom entropy, mandatory CA/name/time validation and TLS 1.2. Keep agent/windows/licenses in enrollment distributions.

The web enrollment downloads a private ZIP with executable, token, CA, configuration and run.cmd. Extract into a protected per-device directory. Run.cmd starts a visible foreground agent; Ctrl+C stops it. No Windows service or update mechanism yet. `--collect F01`, `--collect F04`, `--collect F08` also run bounded local native collections. `--probe agent.conf` checks TLS/authentication without claiming jobs.

## XP lab route

Default tools/xp_lab_console.py is offline. --cirrus --pilot-cd --pilot-network opts into one restricted QEMU guestfwd: 10.0.2.100:8443 → 127.0.0.1:8443. No general route, inbound host forwarding or shared directory. Windows password/ACL provision marker must match the working disk inode. It is not a substitute for inspecting credentials after restoring an existing disk in place. Original clean baseline has a blank Administrator password and must stay offline. Current pilot working disk has a generated password stored in work/private/xp-pilot-admin.txt.

Controller commands are `screen`, `status`, `text <ASCII>`, `key ctrl c` (space-separated simultaneous keys), `password` (types the fixed local lab password) and `quit`. Shut Windows down with `shutdown -s -t 0` before ending the controller. Direct socket guestfwd avoids the failed subprocess backend, which triggered host SIGSYS. Its eager reconnects can cause idle TLS handshake timeouts in the lab; they are not evidence of successful authentication. Actual job result reports are the success evidence. UI considers the last contact within 60 seconds online; this is a recent-heartbeat indicator, not a continuous health guarantee.

## Verification and limits

scripts/check.sh runs Go vet/race tests/build, 40 Python checks, historical OpenAPI syntax, both front-end JS syntax checks. Native import inspection is part of build-agent.sh. Real XP reports are separate: outputs/xp-native-collectors-2026-10-13.json and xp-pilot-e2e-2026-10-13.json. Never substitute unit tests or imports for Windows runtime coverage. The browser automation tool rejected access to its existing tab; actual browser interactions remain unverified unless the user confirms them. No alternate browser workaround was attempted.

See PILOT-PROTOCOL.md for auth, scope, retries, caps and unfinished security architecture. The current x86 executable is a compatibility candidate for later x64 Windows through WoW64, not proof of that compatibility. The final Windows matrix, 50 collectors and release gates remain open.

---

# Historical synthetic scaffold (T011)

This is the T011 synthetic scaffold, authorized alongside legacy work by R15. It is not a production service or an agent control plane. It never connects to the XP VM and cannot execute a collector.

## Linux quick start

From the repository root (Python 3.12+, Linux x86-64):

```sh
python3 scripts/bootstrap.py
./scripts/check.sh
work/bin/forensics-console --demo
```

Open http://127.0.0.1:8080 and choose **Otvoriť lokálne demo**. Ctrl+C stops a foreground server. Port 8080 is fixed for this development version. The process listens only on IPv4 loopback. Do not expose it using a tunnel, reverse proxy or public binding. Under a sandbox, network download/listen and Git metadata may require an authorized escalation.

Go 1.27.1 is project-local, pinned with the official download SHA-256. No third-party Go dependencies. All Go caches stay in work/. Use scripts/go.sh; it disables automatic toolchain/module downloads and scopes no secrets into the build. `work/go.mod` is a nested experimental module boundary to prevent `go test ./...` discovering the toolchain's own test corpus. The check script also scopes paths explicitly. Race tests require a C compiler; verified here with gcc. Node 24.21.0 was verified locally against official SHASUMS and is only an optional JS syntax checker, not needed to build or run the frontend.

## Layout

- cmd/console: loopback server, timeouts, graceful shutdown.
- internal/console: synthetic customer inventory, per-session grants, non-executable plans and embedded web assets.
- internal/console/collectors.json: 50 planned actions copied from design document 03; not capabilities detected on actual agents.
- internal/console/web: browser-native HTML/CSS/JavaScript. React/TypeScript was a proposal, not a requirement; this small initial UI needs no npm build. Re-evaluate when the production interface grows.
- docs/api/openapi.json: OpenAPI 3.1 snapshot of implemented demo routes, not T012's final signed agent protocol.
- tools/: lab preparation, separate from the SaaS and agent.
- outputs/: backlog, decisions, laboratory evidence and milestone reports.
- work/: ignored downloaded media, generated binaries, toolchains, VM disks and local experiments.

## Demo trust boundaries

The session button creates the same fixed synthetic analyst identity with grants to Alfa and Beta. It is not account registration, OIDC, MFA or production login. Every session represents that same demo identity and may access its drafts. The third customer belongs to another MSP and is deliberately not returned. Customer grants and organization membership must both match; endpoint IDs are checked inside the selected customer. Route tests cover cross-customer references.

Sessions are random opaque 256-bit identifiers in HttpOnly SameSite=Strict cookies, 8-hour TTL, maximum 100 live sessions. Cookies are intentionally not Secure only because this isolated demo uses HTTP loopback; production must use HTTPS/Secure cookies and an OIDC-backed session. All mutations, including demo session creation/deletion, require an exact same-origin Origin header. Host allowlist protects against ordinary DNS rebinding; there is no CORS opt-in. Responses are no-store and carry CSP/nosniff/referrer-policy. These measures are not a production security certification.

Plans accept only customer_id, endpoint_ids (1–10 distinct entries), and collector_id (F01/F04/F08). Unknown/duplicate/case-variant fields, null/missing required values, trailing JSON, invalid endpoints and oversized bodies are rejected. The digest covers deterministic serialization of the sorted demo input; it is **not** a signed job/approval envelope. Plans expire after 15 minutes, capacity is 1,000. All storage is memory-only; restart clears sessions and plans. POST /v1/jobs always refuses with 409. UI text is rendered with textContent, not evidence-driven HTML.

There is no agent enrollment, persistence, evidence storage, actual collector, AI provider/MCP, E2EE, billing or paid license implementation. The Free banner is an internal placeholder without trackers or external requests. Synthetic IPs use documentation ranges. Health means the demo process responds, not that product dependencies or endpoints are healthy.

## Container recipe (not run on this host)

Dockerfile provides a Go 1.27.1 build and a scratch/non-root runtime. compose.yaml is a **Linux-only local recipe** using host networking because the binary binds loopback; the container receives no host mounts and still only listens on 127.0.0.1. Read-only filesystem, dropped capabilities, no-new-privileges and resource limits are specified. No Docker engine/CLI was available, so image pull/build and `docker compose up --build` remain unverified. Pin base-image digests and verify the container before CI or production adoption.

## Evidence and next work

See outputs/15-platforma-a-xp-instalacia.md. Next platform work: T013 OIDC/MFA, then T014 actual memberships/RBAC; T015 concerns the Windows build/signing process; keep their acceptance gates. T012's signed/versioned jobs still require the legacy/crypto experiments. The local API is intentionally provisional. No current UI status is proof of XP/7 runtime compatibility.

## Supplemental Windows 7 pilot lab

Windows7Ultimate SP1 x86 is now an installed supplemental profile; it does not certify W02/W03 Professional. Boot with `python3 tools/windows_lab_console.py --profile tools/lab/win7-ultimate-sp1-x86.json --pilot-cd --pilot-network` only after the offline credentials marker exists. The default remains offline. Private CD and password live under ignored work/; commands and restricted route are documented in the latest handoff.

Windows7 provisioning must restrict the C:\pilot **directory** to the operator, SYSTEM and Administrators, then reset **children** to inherit those permissions (`icacls C:\pilot\* /reset /t`). Applying `/inheritance:r` recursively with directory-only OI/CI grants left empty file DACLs during the first test; this was repaired and the source preparation script corrected. Check both directory and executable ACLs and actually execute as the unelevated user before accepting provision success. The [Microsoft icacls reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls) explains inheritance/reset; actual Windows7 behavior is recorded in outputs/win7-provision-2026-10-13.json.

The private ISO was rebuilt with corrected provisioning after a clean VM shutdown. The installed disk was repaired directly and the agent executed successfully as the unelevated operator. Full fresh-disk provisioning has not been repeated with the corrected ISO.

## Collector transparency and updates (14 October 2026)

Implemented sources now live in collectors/windows, with one explicit catalog.
The user clarified R21: source code belongs in a future GitHub repository, not
in the customer GUI or enrollment/update downloads. Source ZIPs are local
release artefacts only. See COLLECTOR-AUTHORING.md, AGENT-AUDIT.md and
COLLECTOR-PACKAGES.md. Current jobs use built-in F01/F04/F08/F15; standalone C
collector EXEs are an offline experiment until signature/worker gates pass.

New approvals use POST /api/jobs/approve with agent_source. The agent reports
capabilities/source on each outbound poll; JOB2 includes the pinned fingerprint.
Legacy agents retain the three original collectors and legacy JOB approvals.
Source reporting is not remote attestation. Manual update ZIPs contain EXE,
manifest/notices only, and preserve the endpoint's existing private identity.

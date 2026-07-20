# OpenClaw Identity

AI agents need to be able to prove who they are. Without a strong identity, there's no reliable way to control what tools an agent can call, audit what it did, or detect if its behavior has been tampered with.

OpenClaw Identity is a reference setup that shows how to give each running [OpenClaw](https://github.com/openclaw/openclaw) agent a cryptographic workload identity using SPIFFE/SPIRE. Once an agent has a verified identity, that identity can be used to enforce tool-level permissions and produce a tamper-evident audit trail — without trusting the agent to self-report who it is.

The setup provides:

- **Workload identity via SPIRE** — each gateway container is automatically issued a short-lived X.509 SVID at runtime, attested by the container's Docker label rather than a static secret
- **Tool authorization via OPA** — every tool call is checked against a policy that maps SPIFFE IDs to permitted tools; calls are blocked if the agent can't prove its identity or OPA is unreachable
- **Audit logging via Fluentd** — each tool call produces a signed, hash-chained audit log entry sent over TCP; calls are blocked if the log can't be written
- **Plugin integrity verification** — a SHA256 hash of the enforcement plugin is stored on the host and checked before each gateway container starts, so a tampered plugin prevents the container from launching

Everything is managed through the **myclawprint** CLI.

---

## Prerequisites

- Docker and Docker Compose
- `openssl` (for certificate generation)
- `npm` (for plugin installation)
- `python3` with `typer` installed

```bash
pip3 install typer
```

---

## Installation

**1. Download the SPIRE agent binary**

`spire-agent-tool` is the SPIRE agent binary mounted into workload containers to fetch SVIDs. It is not included in the repo — download it for your platform:

```bash
# Linux (amd64)
curl -Lo /tmp/spire.tar.gz https://github.com/spiffe/spire/releases/download/v1.14.6/spire-1.14.6-linux-amd64-musl.tar.gz
tar -xzf /tmp/spire.tar.gz -C /tmp
cp /tmp/spire-1.14.6/bin/spire-agent ./spire-agent-tool
chmod +x spire-agent-tool
```

**2. Make the CLI executable**

```bash
chmod +x myclawprint
```

Optionally add it to your PATH:

```bash
export PATH="$PATH:$(pwd)"
```

Run `myclawprint --help` at any time to see available commands.

> **Note:** `spire-agent-certs/` is gitignored — certificates are generated locally and never committed. After cloning, run `python3 myclawprint setup certs` to generate them before starting the stack.

---

## First-time setup

```bash
python3 myclawprint setup all
```

This runs the full install sequence:

1. Creates required directories (`spire-agent-certs/`, `audit-logs/`, `policy/`, `plugin-hashes/`)
2. Generates the SPIRE agent certificate (x509pop attestation)
3. Adds gateway(s) to `docker-compose.yml`
4. Seeds the default OPA policy before starting OPA
5. Sets correct ownership on SPIRE data directories
6. Starts infrastructure (SPIRE server, SPIRE agent, Fluentd, OPA)
7. Installs the plugin into each gateway workspace and writes its integrity hash to `plugin-hashes/`
8. Starts gateways — the verifier container checks the hash before each gateway is allowed to start
9. Runs the interactive OpenClaw onboarding process for each gateway
10. Registers the plugin in each gateway's `openclaw.json` and restarts to activate it
11. Registers each gateway as a SPIRE workload

To create multiple gateways in one shot:

```bash
python3 myclawprint setup all --gateways 2
```

To skip the interactive onboarding step:

```bash
python3 myclawprint setup all --skip-onboard
```

---

## Adding a new gateway

```bash
python3 myclawprint gateway add 2
```

This will:

1. Create `~/.openclaw_openclaw-gateway-2/workspace`
2. Add `openclaw-gateway-2` (plus its verifier and CLI containers) to `docker-compose.yml`
3. Install the plugin and write the integrity hash to `plugin-hashes/openclaw-gateway-2.sha256`
4. Start the gateway — the verifier checks the hash before the container launches
5. Run the interactive OpenClaw onboarding
6. Register the plugin in `openclaw.json` and restart to activate it
7. Register the gateway as a SPIRE workload with SPIFFE ID `spiffe://example.org/ns/apps/sa/openclaw-gateway-2`

The gateway is tracked in `.services` so future `myclawprint identity register` and `policy seed` calls include it automatically.

### Custom service name and label

You can control the Docker Compose service name and the Docker `app` label (which determines the SPIFFE ID) independently:

```bash
# Custom name — label defaults to match
python3 myclawprint gateway add 3 --name research-agent

# Name and label fully independent
python3 myclawprint gateway add 3 --name research-agent --label spiffe-research
# → Docker service:  research-agent
# → Docker label:    app=spiffe-research
# → SPIFFE ID:       spiffe://example.org/ns/apps/sa/spiffe-research
```

---

## Managing gateways

| Command | Description |
|---------|-------------|
| `myclawprint setup start` | Start all containers |
| `myclawprint setup stop` | Stop all containers |
| `myclawprint setup restart` | Restart all containers |
| `myclawprint setup status` | Show running container status |
| `myclawprint gateway list` | List tracked gateways (from `.services`) |
| `myclawprint gateway validate` | Check that each service has a matching `app` label in Docker |
| `myclawprint gateway refresh <N>` | Rewrite a gateway's compose entries to pick up template changes |

### Refreshing an existing gateway

`gateway refresh` rewrites the compose entries for a gateway (the gateway service, its verifier, and its CLI container) using the current templates. Use this after updating myclawprint if the templates have changed — for example, if the verifier command was updated to show a better error message:

```bash
python3 myclawprint gateway refresh 1

# Then recreate the affected containers to apply the changes
docker compose up -d --force-recreate plugin-verifier-1 openclaw-gateway-1 openclaw-cli-1
```

---

## SPIRE workload identity

Each gateway container is assigned a SPIFFE ID of the form:

```
spiffe://example.org/ns/apps/sa/<label>
```

where `<label>` is the Docker `app` label set on the container (defaults to the service name).

| Command | Description |
|---------|-------------|
| `myclawprint identity register` | Register all tracked gateways with SPIRE |
| `myclawprint identity register <svc> ...` | Register specific services only |
| `myclawprint identity list` | Show all registered SPIRE workload entries |
| `myclawprint identity delete-all` | Delete all SPIRE workload entries (prompts for confirmation) |
| `myclawprint identity agent-id` | Print the current SPIRE agent SPIFFE ID |
| `myclawprint identity fetch <service>` | Fetch and display the X.509 SVID for a running container |

---

## OPA tool permissions

Each gateway identity has an explicit list of tools it is permitted to call. Permissions are stored in `policy/openclaw.rego` and reloaded by OPA automatically on change.

> **Note:** `policy/` is gitignored. `myclawprint setup all` seeds it automatically before starting OPA. You can also run `python3 myclawprint policy seed` manually after cloning to generate a starter policy, then customise it for your deployment.

Default permitted tools are `read` and `write`.

**Grant a tool to an identity:**

```bash
python3 myclawprint policy grant openclaw-gateway-1 exec
```

**Revoke a tool:**

```bash
python3 myclawprint policy revoke openclaw-gateway-1 exec
```

**List all identities and their permitted tools:**

```bash
python3 myclawprint policy list
```

**Seed default permissions** (writes a baseline policy for all tracked gateways):

```bash
python3 myclawprint policy seed
```

You can also edit `policy/openclaw.rego` directly — OPA picks up changes automatically via `--watch`.

---

## Certificates

The SPIRE agent authenticates to the SPIRE server using an x509pop certificate stored in `spire-agent-certs/`. These are generated automatically by `myclawprint setup all` and are valid for 365 days.

To regenerate certificates (e.g. on expiry):

```bash
python3 myclawprint setup certs --force
```

After regenerating, recreate the containers so the new certs are picked up and the agent re-attests:

```bash
docker compose stop spire-server spire-agent
docker compose rm -f spire-server spire-agent
docker compose up -d
```

> After re-attestation the agent will have a new fingerprint. Re-run `python3 myclawprint identity register` to update workload entries with the new parent ID.

---

## Plugin: SPIFFE Zero Trust Enforcer

The `plugin/` directory contains the `spiffe-security-enforcer` OpenClaw plugin. It runs inside each gateway and:

- **Watches the SPIFFE SVID** — maintains the current workload identity via the SPIRE agent socket; clears identity if the stream ends (fail closed)
- **Enforces OPA policy** — checks every tool call against `policy/openclaw.rego` before allowing it; blocks the call if OPA is unreachable
- **Signs audit logs** — sends a tamper-evident, hash-chained audit entry to Fluentd for every tool call, signed with the SVID private key; blocks the call if Fluentd is disconnected

The plugin fails closed on all three conditions — a tool call is blocked if the gateway cannot prove its identity, get authorization, or record the audit log.

### Plugin integrity verification

Before each gateway container starts, a Docker `plugin-verifier-N` container mounts the gateway's plugin directory (read-only) and the `plugin-hashes/` directory (read-only from the host) and runs:

```
sha256sum -c /hashes/<gateway-name>.sha256
```

If the hash doesn't match — or the hash file doesn't exist — the verifier exits with an error and Docker refuses to start the gateway. Because `plugin-hashes/` is on the host and never mounted writable into any container, a compromised container cannot update the hash to cover its tracks.

| Command | Description |
|---------|-------------|
| `myclawprint gateway verify-plugin` | Check all gateways' installed plugins against their stored hashes |
| `myclawprint gateway rehash-plugin <N>` | Regenerate the hash after an intentional plugin change |
| `myclawprint gateway install-plugin <N>` | Reinstall the plugin from source and update the hash |

If you intentionally modify the installed plugin at `~/.openclaw_<name>/extensions/spiffe-security-enforcer/index.ts`, you must regenerate the hash or the gateway will be blocked from starting on the next restart:

```bash
python3 myclawprint gateway rehash-plugin 1

# With a custom service name
python3 myclawprint gateway rehash-plugin 1 --name research-agent
```

This updates `plugin-hashes/<name>.sha256` on the host to match the current plugin. After rehashing, verify the gateway can start:

```bash
docker compose up -d openclaw-gateway-1
```

> **Note:** `rehash-plugin` should only be used after a deliberate, reviewed change. If `verify-plugin` reports a mismatch you did not expect, treat it as a potential tampering alert and investigate before rehashing.

### Installing the plugin

The plugin is installed automatically by `myclawprint setup all` and `myclawprint gateway add`. The install process:

1. Copies `plugin/` into `~/.openclaw_<name>/extensions/spiffe-security-enforcer/`
2. Runs `npm install` in the copied directory
3. Writes a SHA256 hash of `index.ts` to `plugin-hashes/<name>.sha256` on the host
4. After onboarding creates `openclaw.json`, enables the plugin in the config and restarts the gateway

To install or reinstall the plugin manually:

```bash
python3 myclawprint gateway install-plugin <N>

# With a custom service name
python3 myclawprint gateway install-plugin <N> --name research-agent
```

To add a gateway without installing the plugin:

```bash
python3 myclawprint gateway add <N> --no-plugin
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OPA_URL` | `http://opa:8181` | OPA server URL |
| `SIEM_HOST` | `fluentd-logger` | Fluentd host for audit logs |
| `SIEM_PORT` | `24224` | Fluentd TCP port |

These are already set correctly in `docker-compose.yml`.

---

## Directory structure

```
.
├── myclawprint                   # CLI entry point
├── cli/
│   ├── main.py                   # top-level Typer app
│   ├── commands/
│   │   ├── setup.py              # myclawprint setup ...
│   │   ├── gateway.py            # myclawprint gateway ...
│   │   ├── identity.py           # myclawprint identity ...
│   │   └── policy.py             # myclawprint policy ...
│   └── utils/
│       ├── compose.py            # docker compose helpers
│       ├── spire.py              # spire-server helpers
│       └── policy.py             # rego manipulation
├── pyproject.toml
├── docker-compose.yml
├── spire-agent-tool              # gitignored; download separately (see Installation)
├── .services                     # gitignored; generated when you add gateways
├── policy/
│   └── openclaw.rego             # gitignored; generated by `myclawprint setup all` or `policy seed`
├── plugin-hashes/                # gitignored; one .sha256 file per gateway, stored on host only
├── plugin/
│   ├── index.ts                  # SPIFFE Zero Trust Enforcer plugin source
│   ├── openclaw.plugin.json      # plugin manifest
│   └── package.json              # npm dependencies
├── spire-server-config/
│   └── server.conf
├── spire-agent-config/
│   └── agent.conf
├── spire-agent-certs/            # gitignored; generated by `myclawprint setup certs`
│   ├── agent.crt.pem
│   └── agent.key.pem
├── audit-logs/                   # gitignored; Fluentd audit output
└── fluent.conf
```

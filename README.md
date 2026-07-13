# Openclaw Identity

Openclaw Identity is a secure AI gateway platform setup that uses:

- **SPIRE** for workload identity — each gateway container receives a cryptographic SPIFFE identity (SVID) at runtime
- **Open Policy Agent (OPA)** for tool authorization — controls which tools each identity is permitted to call
- **Fluentd** for audit logging

Infrastructure is managed through the **myclawprint** CLI.

---

## Prerequisites

- Docker and Docker Compose
- `openssl` (for certificate generation)
- `python3` with `typer` installed
- `sudo` access (required once to set ownership on SPIRE data directories)

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

1. Creates required directories
2. Generates the SPIRE agent certificate (x509pop attestation)
3. Sets correct ownership on SPIRE data directories
4. Runs the interactive Openclaw onboarding process for each gateway
5. Starts all containers
6. Waits for SPIRE server to be healthy
7. Registers each gateway as a SPIRE workload

After setup, seed the default OPA permissions and verify a gateway received its identity:

```bash
python3 myclawprint policy seed
python3 myclawprint identity fetch openclaw-gateway
```

---

## Adding a new gateway

```bash
python3 myclawprint gateway add 3
```

This will:

1. Create `~/.openclaw_openclaw-gateway-3/workspace`
2. Add `openclaw-gateway-3` to `docker-compose.yml` with label `app=openclaw-gateway-3`
3. Run the interactive Openclaw onboarding for the new gateway
4. Register it as a SPIRE workload with SPIFFE ID `spiffe://example.org/ns/apps/sa/openclaw-gateway-3`

Then start it:

```bash
docker compose up -d openclaw-gateway-3
```

The gateway is tracked in `.services` so future `myclawprint identity register` calls include it automatically.

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
| `myclawprint gateway onboard <N>` | Re-run onboarding for a specific gateway |

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

> **Note:** `policy/` is gitignored. Run `python3 myclawprint policy seed` after cloning to generate a starter policy, then customise it for your deployment.

**Grant a tool to an identity:**

```bash
# Short service name
python3 myclawprint policy grant openclaw-gateway read_file

# Full SPIFFE ID
python3 myclawprint policy grant spiffe://example.org/ns/apps/sa/openclaw-gateway read_file
```

**Revoke a tool:**

```bash
python3 myclawprint policy revoke openclaw-gateway write_file
```

**List all identities and their permitted tools:**

```bash
python3 myclawprint policy list
```

**Seed default permissions** (writes a baseline policy for all default gateways):

```bash
python3 myclawprint policy seed
```

You can also edit `policy/openclaw.rego` directly — OPA picks up changes automatically via `--watch`.

---

## Certificates

The SPIRE agent authenticates to the SPIRE server using an x509pop certificate stored in `spire-agent-certs/`. These are generated automatically by `myclawprint setup all` and are valid for 365 days.

To regenerate certificates (e.g. on expiry):

```bash
python3 myclawprint setup certs       # generates new certs (skips if present)
```

Or to force regeneration, remove the existing certs first:

```bash
rm spire-agent-certs/agent.crt.pem spire-agent-certs/agent.key.pem
python3 myclawprint setup certs
python3 myclawprint setup stop
python3 myclawprint setup start
```

> After regenerating certs the SPIRE agent will re-attest with a new fingerprint.
> Re-run `python3 myclawprint identity register` to update workload entries with the new parent ID.

---

## Plugin: SPIFFE Zero Trust Enforcer

The `plugin/` directory contains the `spiffe-security-enforcer` Openclaw plugin. It runs inside each gateway and:

- **Watches the SPIFFE SVID** — maintains the current workload identity via the SPIRE agent socket
- **Enforces OPA policy** — checks every tool call against `policy/openclaw.rego` before allowing it; fails closed if OPA is unreachable
- **Signs audit logs** — sends a tamper-evident, hash-chained audit entry to Fluentd for every tool call, signed with the SVID private key

### Installing the plugin

The plugin is installed automatically when you run `myclawprint gateway add`. The install process:

1. Copies `plugin/` into the gateway's extensions directory
2. Runs `npm install`
3. Registers the plugin: `openclaw plugins install npm-pack:/path/to/plugin`
4. Enables the plugin: `openclaw plugins enable spiffe-security-enforcer`
5. Restarts the gateway to activate it

If the gateway container isn't running yet when `gateway add` is called, the plugin files are copied and npm-installed on the host, and a reminder is printed to run `install-plugin` once the container is up.

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
│   └── openclaw.rego             # gitignored; generated by `myclawprint policy seed`
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

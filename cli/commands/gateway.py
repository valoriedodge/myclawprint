import hashlib
import json
import re
import subprocess
from pathlib import Path

import typer
from typing import List, Optional

from ..utils import compose, spire

app = typer.Typer(help="Manage openclaw gateway containers.")

PROJECT_DIR   = Path(__file__).parent.parent.parent
COMPOSE_FILE  = PROJECT_DIR / "docker-compose.yml"
SERVICES_FILE = PROJECT_DIR / ".services"
BASE_PORT     = 18789
TRUST_DOMAIN  = "example.org"

PLUGIN_SRC  = PROJECT_DIR / "plugin"
PLUGIN_NAME = "spiffe-security-enforcer"
HASHES_DIR  = PROJECT_DIR / "plugin-hashes"

# Files to skip when hashing the plugin
_HASH_SKIP = {"node_modules", ".git", "__pycache__"}


def _hash_file(name: str) -> Path:
    return HASHES_DIR / f"{name}.sha256"


def _default_name(n: int) -> str:
    return f"openclaw-gateway-{n}"


def _default_cli_name(n: int) -> str:
    return f"openclaw-cli-{n}"


def _default_verifier_name(n: int) -> str:
    return f"plugin-verifier-{n}"


def _workspace_dir(name: str) -> Path:
    return Path.home() / f".openclaw_{name}"


def _cli_workspace_dir(n: int) -> Path:
    return Path.home() / f".openclaw_cli_{n}"


def _host_port(n: int) -> int:
    return BASE_PORT + n * 100


def _compute_plugin_hash(dest: Path) -> str:
    """Hash the installed index.ts. Returns a sha256sum-compatible line relative to the workspace."""
    index_ts = dest / "index.ts"
    digest = hashlib.sha256(index_ts.read_bytes()).hexdigest()
    return f"{digest}  extensions/{PLUGIN_NAME}/index.ts\n"


def _service_block(n: int, name: str, label: str) -> str:
    port_var      = f"OPENCLAW_GATEWAY_{n}_PORT"
    home          = _workspace_dir(name)
    verifier_name = _default_verifier_name(n)
    return f"""
  {name}:
    image: ghcr.io/openclaw/openclaw:latest
    command: ["node", "openclaw.mjs", "gateway", "--bind", "lan", "--port", "18789"]
    restart: unless-stopped
    environment:
      - SPIFFE_ENDPOINT_SOCKET=unix:///opt/spire/sockets/agent.sock
      - OPENCLAW_DISABLE_BONJOUR=true
      - SIEM_HOST=fluentd-logger
      - SIEM_PORT=24224
    volumes:
      - {home}:/home/node/.openclaw
      - {home}/workspace:/home/node/.openclaw/workspace
      - spire-agent-sockets:/opt/spire/sockets:ro
      - ./spire-agent-tool:/bin/spire-agent-tool:ro
    ports:
      - "${{{port_var}:-{_host_port(n)}}}:18789"
    labels:
      - "app={label}"
    cap_drop:
      - NET_RAW
      - NET_ADMIN
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD", "node", "-e", "fetch('http://127.0.0.1:18789/healthz').then(r => process.exit(r.ok ? 0 : 1))"]
      interval: 30s
      timeout: 5s
      retries: 5
      start_period: 20s
    depends_on:
      {verifier_name}:
        condition: service_completed_successfully
      spire-agent:
        condition: service_started
      fluentd-logger:
        condition: service_started
"""


def _verifier_block(n: int, name: str) -> str:
    verifier_name = _default_verifier_name(n)
    home          = _workspace_dir(name)
    return f"""
  {verifier_name}:
    image: alpine
    volumes:
      - {home}:/workspace:ro
      - {HASHES_DIR}:/hashes:ro
    working_dir: /workspace
    command: ["sh", "-c", "sha256sum -c /hashes/{name}.sha256 && echo '[ok] Plugin integrity verified' || (echo '[FAIL] Plugin integrity check failed for {name} - run: python3 myclawprint gateway verify-plugin' && exit 1)"]
    restart: "no"
"""


def _cli_block(n: int, gateway_name: str) -> str:
    cli_name = _default_cli_name(n)
    home     = _cli_workspace_dir(n)
    return f"""
  {cli_name}:
    image: ghcr.io/openclaw/openclaw:latest
    network_mode: "service:{gateway_name}"
    environment:
      - SPIFFE_ENDPOINT_SOCKET=unix:///opt/spire/sockets/agent.sock
      - BROWSER=echo
    volumes:
      - {home}:/home/node/.openclaw
      - {home}/workspace:/home/node/.openclaw/workspace
      - spire-agent-sockets:/opt/spire/sockets:ro
      - ./spire-agent-tool:/bin/spire-agent-tool:ro
    labels:
      - "app={cli_name}"
    security_opt:
      - no-new-privileges:true
    stdin_open: true
    tty: true
    init: true
    depends_on:
      - {gateway_name}
    entrypoint: ["node", "dist/index.js"]
"""


def _tracked_services() -> List[str]:
    if SERVICES_FILE.exists():
        return [s for s in SERVICES_FILE.read_text().split() if s]
    return []


def _track_service(name: str) -> None:
    existing = _tracked_services()
    if name not in existing:
        with SERVICES_FILE.open("a") as f:
            f.write(f"{name}\n")


def _patch_origins(workspace: Path, port: int) -> None:
    """Add the gateway's localhost origin to allowedOrigins in openclaw.json if not present."""
    config_file = workspace / "openclaw.json"
    if not config_file.exists():
        return

    origin = f"http://localhost:{port}"
    config = json.loads(config_file.read_text())
    origins = config.setdefault("gateway", {}).setdefault("controlUi", {}).setdefault("allowedOrigins", [])
    if origin not in origins:
        origins.append(origin)
        config_file.write_text(json.dumps(config, indent=2))
        typer.echo(f"  [ok] Added '{origin}' to allowedOrigins")
    else:
        typer.echo(f"  [info] '{origin}' already in allowedOrigins")


def _install_plugin(name: str, workspace: Path) -> None:
    """Copy plugin source to extensions/, npm install, and write hash file."""
    import shutil

    if not PLUGIN_SRC.exists():
        typer.echo(f"[error] Plugin source not found at {PLUGIN_SRC}", err=True)
        raise typer.Exit(1)

    dest = workspace / "extensions" / PLUGIN_NAME
    typer.echo(f"→ Copying plugin to {dest} ...")
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(PLUGIN_SRC, dest)
    typer.echo(f"  [ok] Copied plugin source")

    typer.echo(f"  Running npm install ...")
    result = subprocess.run(["npm", "install"], cwd=dest, capture_output=True, text=True)
    if result.returncode != 0:
        typer.echo(f"[error] npm install failed:\n{result.stdout}{result.stderr}", err=True)
        raise typer.Exit(1)
    typer.echo(f"  [ok] npm install complete")

    typer.echo(f"  Writing plugin integrity hash ...")
    HASHES_DIR.mkdir(parents=True, exist_ok=True)
    manifest = _compute_plugin_hash(dest)
    _hash_file(name).write_text(manifest)
    typer.echo(f"  [ok] Hash written to {_hash_file(name)}")


def _run_onboard(name: str) -> None:
    """Run openclaw onboard interactively inside an already-running gateway container."""
    try:
        compose.run_interactive(name, "bash", "-c", "openclaw onboard")
    except subprocess.CalledProcessError:
        typer.echo(f"  [warn] Onboarding skipped or failed for {name}")


def _post_install(name: str, n: int) -> None:
    """Register plugin in openclaw.json and restart container (call after onboarding creates the config)."""
    workspace = _workspace_dir(name)
    config_file = workspace / "openclaw.json"
    if not config_file.exists():
        typer.echo(f"  [warn] openclaw.json not found for {name} — plugin entry not registered.")
        return

    config = json.loads(config_file.read_text())
    entries: dict = config.setdefault("plugins", {}).setdefault("entries", {})
    if entries.get(PLUGIN_NAME, {}).get("enabled"):
        typer.echo(f"  [skip] Plugin already registered in openclaw.json for {name}")
        return

    entries.setdefault(PLUGIN_NAME, {})["enabled"] = True
    config_file.write_text(json.dumps(config, indent=2))
    typer.echo(f"  [ok] Registered '{PLUGIN_NAME}' in openclaw.json")
    typer.echo(f"  Restarting {name} to activate plugin ...")
    compose.run("restart", name)
    typer.echo(f"  [ok] {name} restarted — plugin active.")


def _register_entry(n: int, name: str, label: str) -> None:
    """Create a SPIRE workload entry for this gateway."""
    parent_id = spire.agent_spiffe_id()
    if not parent_id:
        typer.echo("  [warn] Could not determine agent SPIFFE ID — skipping registration.")
        typer.echo("  Run 'myclawprint identity register' manually after the agent is running.")
        return

    result = spire.create_entry(
        parent_id=parent_id,
        spiffe_id=f"spiffe://{TRUST_DOMAIN}/ns/apps/sa/{label}",
        selector=f"docker:label:app:{label}",
    )
    combined = (result.stdout or "") + (result.stderr or "")
    if result.returncode == 0:
        typer.echo(f"  [ok] Registered SPIRE entry: spiffe://{TRUST_DOMAIN}/ns/apps/sa/{label}")
    elif "already exists" in combined:
        typer.echo(f"  [skip] SPIRE entry already registered")
    else:
        typer.echo(f"  [warn] SPIRE registration failed:\n{combined}", err=True)


def add_to_compose(n: int, name: str, label: str) -> None:
    """Add a gateway + verifier + CLI to docker-compose.yml and track the gateway."""
    content      = COMPOSE_FILE.read_text()
    cli_name     = _default_cli_name(n)
    verifier_name = _default_verifier_name(n)

    if f"  {name}:" in content:
        typer.echo(f"  [info] '{name}' already in docker-compose.yml")
    else:
        (_workspace_dir(name) / "workspace").mkdir(parents=True, exist_ok=True)
        (_cli_workspace_dir(n) / "workspace").mkdir(parents=True, exist_ok=True)

        block   = _verifier_block(n, name) + _service_block(n, name, label) + _cli_block(n, name)
        updated = re.sub(r'(\nvolumes:)', block + r'\1', content)
        if updated == content:
            typer.echo("[error] Could not find insertion point in docker-compose.yml", err=True)
            raise typer.Exit(1)
        COMPOSE_FILE.write_text(updated)
        typer.echo(f"  [ok] Added '{name}', '{verifier_name}', and '{cli_name}' to docker-compose.yml")
    _track_service(name)


def configure_running(n: int, name: str, label: str, skip_onboard: bool = False) -> None:
    """Onboard, install plugin, patch origins, and register SPIRE entry for a running container."""
    workspace = _workspace_dir(name)

    if not skip_onboard:
        typer.echo(f"── Onboarding {name} ──")
        _run_onboard(name)

    _install_plugin(name, workspace)
    _post_install(name, n)
    _patch_origins(workspace, _host_port(n))
    _register_entry(n, name, label)


@app.command()
def add(
    n: int = typer.Argument(..., help="Gateway number, used for port assignment and defaults."),
    name: str = typer.Option(None, "--name", help="Service name (default: openclaw-gateway-N)."),
    label: str = typer.Option(None, "--label", help="Docker 'app' label and SPIFFE ID suffix (default: same as --name)."),
    no_onboard: bool = typer.Option(False, "--no-onboard", help="Skip interactive onboarding."),
    no_register: bool = typer.Option(False, "--no-register", help="Skip SPIRE workload registration."),
    no_plugin: bool = typer.Option(False, "--no-plugin", help="Skip plugin installation."),
) -> None:
    """Add a new gateway to docker-compose, install plugin, onboard, and register.

    The --label controls both the Docker 'app' label and the SPIFFE ID:
      spiffe://example.org/ns/apps/sa/<label>

    Example:
      myclawprint gateway add 3 --name research-agent --label research-agent
    """
    name  = name  or _default_name(n)
    label = label or name

    add_to_compose(n, name, label)

    if not no_plugin:
        typer.echo(f"→ Installing plugin (writing integrity hash before gateway start)...")
        _install_plugin(name, _workspace_dir(name))

    typer.echo(f"→ Starting {name} ...")
    compose.run("up", "-d", name)

    if not no_onboard:
        _run_onboard(name)
        if not no_plugin:
            _post_install(name, n)

    _patch_origins(_workspace_dir(name), _host_port(n))

    if not no_register:
        _register_entry(n, name, label)

    typer.echo(f"\nDone. Gateway '{name}' is running on port {_host_port(n)}.")


@app.command()
def refresh(
    n: int = typer.Argument(..., help="Gateway number to refresh."),
    name: str = typer.Option(None, "--name", help="Service name (default: openclaw-gateway-N)."),
    label: str = typer.Option(None, "--label", help="Docker 'app' label (default: same as --name)."),
) -> None:
    """Rewrite a gateway's docker-compose entries to pick up template changes (e.g. adding the verifier)."""
    name  = name  or _default_name(n)
    label = label or name
    cli_name      = _default_cli_name(n)
    verifier_name = _default_verifier_name(n)

    content = COMPOSE_FILE.read_text()

    # Remove existing blocks for this gateway, its cli, and its verifier
    for svc in [verifier_name, name, cli_name]:
        # Match from "  <svc>:\n" up to the next top-level service or volumes:
        content = re.sub(
            rf'\n  {re.escape(svc)}:.*?(?=\n  \S|\nvolumes:)',
            '',
            content,
            flags=re.DOTALL,
        )

    block   = _verifier_block(n, name) + _service_block(n, name, label) + _cli_block(n, name)
    updated = re.sub(r'(\nvolumes:)', block + r'\1', content)
    if updated == content:
        typer.echo("[error] Could not find insertion point in docker-compose.yml", err=True)
        raise typer.Exit(1)

    COMPOSE_FILE.write_text(updated)
    typer.echo(f"  [ok] Refreshed '{name}', '{verifier_name}', and '{cli_name}' in docker-compose.yml")
    typer.echo(f"  Run 'docker compose up -d {name}' to apply.")


@app.command(name="list")
def list_gateways() -> None:
    """List all tracked gateways."""
    services = _tracked_services()
    if not services:
        typer.echo("No gateways tracked yet. Run 'myclawprint gateway add <N>' to add one.")
        return
    typer.echo("Tracked gateways:")
    for svc in services:
        typer.echo(f"  {svc}")


@app.command()
def rehash_plugin(
    n: int = typer.Argument(..., help="Gateway number."),
    name: str = typer.Option(None, "--name", help="Service name (default: openclaw-gateway-N)."),
) -> None:
    """Regenerate the plugin hash for a gateway after intentional plugin changes."""
    name      = name or _default_name(n)
    workspace = _workspace_dir(name)
    dest      = workspace / "extensions" / PLUGIN_NAME

    if not (dest / "index.ts").exists():
        typer.echo(f"[error] Plugin not installed at {dest}", err=True)
        raise typer.Exit(1)

    HASHES_DIR.mkdir(parents=True, exist_ok=True)
    manifest = _compute_plugin_hash(dest)
    _hash_file(name).write_text(manifest)
    typer.echo(f"  [ok] Hash updated for '{name}' at {_hash_file(name)}")


@app.command()
def install_plugin(
    n: int = typer.Argument(..., help="Gateway number."),
    name: str = typer.Option(None, "--name", help="Service name (default: openclaw-gateway-N)."),
) -> None:
    """Install and enable the spiffe-security-enforcer plugin in a gateway."""
    name = name or _default_name(n)
    workspace = _workspace_dir(name)
    _install_plugin(name, workspace)
    _post_install(name, n)


@app.command()
def verify_plugin() -> None:
    """Check that each gateway's installed plugin matches its stored hash (tamper detection)."""
    services = _tracked_services()
    if not services:
        typer.echo("No tracked gateways.")
        return

    errors = 0
    for svc in services:
        workspace  = _workspace_dir(svc)
        hash_file  = _hash_file(svc)
        index_ts   = workspace / "extensions" / PLUGIN_NAME / "index.ts"

        if not hash_file.exists():
            typer.echo(f"  [FAIL] {svc}: no hash file — run 'myclawprint gateway install-plugin'")
            errors += 1
            continue
        if not index_ts.exists():
            typer.echo(f"  [FAIL] {svc}: plugin not installed")
            errors += 1
            continue

        current = _compute_plugin_hash(workspace / "extensions" / PLUGIN_NAME)
        stored  = hash_file.read_text()
        if current == stored:
            digest = current.split()[0][:16]
            typer.echo(f"  [ok]   {svc}: {digest}...")
        else:
            typer.echo(f"  [FAIL] {svc}: plugin has been modified since installation", err=True)
            errors += 1

    if errors:
        raise typer.Exit(1)


@app.command()
def validate() -> None:
    """Check that each tracked gateway has a matching 'app' label in Docker."""
    services = _tracked_services()
    if not services:
        typer.echo("No tracked gateways.")
        return

    errors = 0
    for svc in services:
        label = compose.container_label(svc, "app")
        if label != svc:
            typer.echo(f"  [FAIL] {svc}: expected label app={svc}, got '{label}'")
            errors += 1
        else:
            typer.echo(f"  [ok]   {svc}: label app={svc}")

    if errors:
        typer.echo("\nFix labels in docker-compose.yml")
        raise typer.Exit(1)

import json
import re
import subprocess
from pathlib import Path

import typer
from typing import List, Optional

from ..utils import compose, spire

app = typer.Typer(help="Manage openclaw gateway containers.")

PROJECT_DIR    = Path(__file__).parent.parent.parent
COMPOSE_FILE   = PROJECT_DIR / "docker-compose.yml"
SERVICES_FILE  = PROJECT_DIR / ".services"
BASE_PORT      = 18789
TRUST_DOMAIN   = "example.org"


PLUGIN_SRC  = PROJECT_DIR / "plugin"
PLUGIN_NAME = "spiffe-security-enforcer"


def _default_name(n: int) -> str:
    return f"openclaw-gateway-{n}"


def _workspace_dir(n: int, name: str) -> Path:
    return Path.home() / f".openclaw_{name}"


def _service_block(n: int, name: str, label: str) -> str:
    port_var  = f"OPENCLAW_GATEWAY_{n}_PORT"
    host_port = BASE_PORT + n * 100
    home      = _workspace_dir(n, name)
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
      - "${{{port_var}:-{host_port}}}:18789"
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
      - spire-agent
      - fluentd-logger
"""


def _patch_openclaw_config(n: int, name: str) -> None:
    """Add the gateway's localhost origin to allowedOrigins in openclaw.json if not present."""
    config_file = _workspace_dir(n, name) / "openclaw.json"
    if not config_file.exists():
        return  # not onboarded yet; onboard will create it

    origin = f"http://localhost:{BASE_PORT + n * 100}"
    config = json.loads(config_file.read_text())

    origins = config.setdefault("gateway", {}).setdefault("controlUi", {}).setdefault("allowedOrigins", [])
    if origin not in origins:
        origins.append(origin)
        config_file.write_text(json.dumps(config, indent=2))
        typer.echo(f"  [ok] Added '{origin}' to allowedOrigins in openclaw.json")
    else:
        typer.echo(f"  [info] '{origin}' already in allowedOrigins")


def _tracked_services() -> List[str]:
    if SERVICES_FILE.exists():
        return [s for s in SERVICES_FILE.read_text().split() if s]
    return []


def _track_service(name: str) -> None:
    existing = _tracked_services()
    if name not in existing:
        with SERVICES_FILE.open("a") as f:
            f.write(f"{name}\n")


@app.command()
def add(
    n: int = typer.Argument(..., help="Gateway number, used for port assignment and defaults."),
    name: str = typer.Option(None, "--name", help="Docker Compose service name (default: openclaw-gateway-N)."),
    label: str = typer.Option(None, "--label", help="Docker 'app' label and SPIFFE ID suffix (default: same as --name)."),
    no_onboard: bool = typer.Option(False, "--no-onboard", help="Skip interactive onboarding."),
    no_register: bool = typer.Option(False, "--no-register", help="Skip SPIRE workload registration."),
    no_plugin: bool = typer.Option(False, "--no-plugin", help="Skip plugin installation."),
) -> None:
    """Add a new gateway: create workspace, update docker-compose, onboard, and register.

    The --label controls both the Docker 'app' label and the SPIFFE ID:
      spiffe://example.org/ns/apps/sa/<label>

    Example:
      myclawprint gateway add 3 --name research-agent --label research-agent
    """
    name  = name  or _default_name(n)
    label = label or name
    content = COMPOSE_FILE.read_text()

    if f"  {name}:" in content:
        typer.echo(f"  [info] '{name}' already exists in docker-compose.yml")
    else:
        ws = _workspace_dir(n, name) / "workspace"
        ws.mkdir(parents=True, exist_ok=True)
        typer.echo(f"  [ok] Created {ws}")

        block   = _service_block(n, name, label)
        updated = re.sub(r'(\nvolumes:)', block + r'\1', content)
        if updated == content:
            typer.echo("[error] Could not find insertion point in docker-compose.yml", err=True)
            raise typer.Exit(1)
        COMPOSE_FILE.write_text(updated)
        typer.echo(f"  [ok] Added '{name}' to docker-compose.yml (port {BASE_PORT + n * 100}, label app={label})")

    _track_service(name)
    typer.echo(f"  [ok] Tracked '{name}' in .services")

    if not no_plugin:
        install_plugin(n, name=name)

    if not no_onboard:
        typer.echo(f"\n── Onboarding {name} ──")
        try:
            compose.run_interactive(name, "bash", "-c", "openclaw onboard")
        except subprocess.CalledProcessError:
            typer.echo(f"  [warn] Onboarding skipped or failed for {name}")

    typer.echo(f"→ Patching openclaw.json ...")
    _patch_openclaw_config(n, name)

    if not no_register:
        parent_id = spire.agent_spiffe_id()
        if not parent_id:
            typer.echo("  [warn] Could not determine agent SPIFFE ID — skipping registration.")
            typer.echo("  Run 'myclawprint identity register' manually after the agent is running.")
        else:
            result = spire.create_entry(
                parent_id=parent_id,
                spiffe_id=f"spiffe://{TRUST_DOMAIN}/ns/apps/sa/{label}",
                selector=f"docker:label:app:{label}",
            )
            if result.returncode == 0:
                typer.echo(f"  [ok] Registered SPIRE entry: spiffe://{TRUST_DOMAIN}/ns/apps/sa/{label}")
            else:
                typer.echo(f"  [warn] SPIRE registration failed:\n{result.stdout}", err=True)

    typer.echo(f"\nDone. Start with: docker compose up -d {name}")


@app.command()
def onboard(
    n: int = typer.Argument(..., help="Gateway number to onboard."),
) -> None:
    """Run the interactive openclaw onboarding for a gateway."""
    name = _gateway_name(n)
    typer.echo(f"── Onboarding {name} ──")
    compose.run_interactive(name, "bash", "-c", "openclaw onboard")


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
def install_plugin(
    n: int = typer.Argument(..., help="Gateway number to install the plugin into."),
    name: str = typer.Option(None, "--name", help="Service name (default: openclaw-gateway-N)."),
) -> None:
    """Install and enable the spiffe-security-enforcer plugin in a gateway."""
    import shutil
    name = name or _default_name(n)
    dest = _workspace_dir(n, name) / "extensions" / PLUGIN_NAME
    container_plugin_path = f"/home/node/.openclaw/extensions/{PLUGIN_NAME}"

    if not PLUGIN_SRC.exists():
        typer.echo(f"[error] Plugin source not found at {PLUGIN_SRC}", err=True)
        raise typer.Exit(1)

    # Copy source and npm install on the host
    typer.echo(f"→ Copying plugin to {dest} ...")
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(PLUGIN_SRC, dest)
    typer.echo(f"  [ok] Copied plugin source")

    typer.echo(f"  Running npm install ...")
    result = subprocess.run(["npm", "install"], cwd=dest, capture_output=True, text=True)
    if result.returncode != 0:
        typer.echo(f"[error] npm install failed:\n{result.stderr}", err=True)
        raise typer.Exit(1)
    typer.echo(f"  [ok] npm install complete")

    # Check if the container is running
    cid = compose.container_id(name)
    if not cid:
        typer.echo(f"  [info] Container '{name}' is not running — plugin will be registered on next start.")
        typer.echo(f"  Run 'docker compose up -d {name}' then 'myclawprint gateway install-plugin {n}' to enable it.")
        return

    # Register and enable via openclaw CLI inside the container
    typer.echo(f"  Registering plugin with openclaw ...")
    result = compose.exec(name, "openclaw", "plugins", "install",
                          f"npm-pack:{container_plugin_path}", capture=True)
    if result.returncode != 0:
        typer.echo(f"[error] Plugin install failed:\n{result.stdout}{result.stderr}", err=True)
        raise typer.Exit(1)
    typer.echo(f"  [ok] Plugin registered")

    typer.echo(f"  Enabling plugin ...")
    result = compose.exec(name, "openclaw", "plugins", "enable", PLUGIN_NAME, capture=True)
    if result.returncode != 0:
        typer.echo(f"[error] Plugin enable failed:\n{result.stdout}{result.stderr}", err=True)
        raise typer.Exit(1)
    typer.echo(f"  [ok] Plugin enabled")

    # Restart to activate
    typer.echo(f"  Restarting {name} to activate plugin ...")
    compose.run("restart", name)
    typer.echo(f"  [ok] {name} restarted — plugin active.")


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

import subprocess
import time
from pathlib import Path

import typer
from typing import List

from ..utils import compose, spire
from . import identity as _identity
from . import gateway as _gateway

app = typer.Typer(help="First-time installation and infrastructure setup.")

PROJECT_DIR = Path(__file__).parent.parent.parent
AGENT_CERT  = PROJECT_DIR / "spire-agent-certs" / "agent.crt.pem"
AGENT_KEY   = PROJECT_DIR / "spire-agent-certs" / "agent.key.pem"


@app.command()
def all(
    gateways: int = typer.Option(1, "--gateways", help="Number of openclaw gateways to create."),
    skip_onboard: bool = typer.Option(False, "--skip-onboard", help="Skip interactive gateway onboarding."),
) -> None:
    """Full first-time setup: dirs, certs, add gateways, permissions, start, configure, register."""
    dirs()
    certs()

    typer.echo(f"→ Adding {gateways} gateway(s) to docker-compose.yml...")
    for n in range(1, gateways + 1):
        name  = _gateway._default_name(n)
        label = name
        _gateway.add_to_compose(n, name, label)

    permissions()

    typer.echo("→ Starting infrastructure...")
    compose.run("up", "-d", "spire-server", "spire-agent", "fluentd-logger", "opa")
    wait()

    typer.echo("→ Configuring gateways (plugin, onboard, origins)...")
    for n in range(1, gateways + 1):
        name  = _gateway._default_name(n)
        label = name
        typer.echo(f"\n── {name} ──")
        _gateway.configure_running(n, name, label, skip_onboard=skip_onboard)

    typer.echo("→ Starting gateways...")
    compose.run("up", "-d")

    typer.echo("\n→ Waiting for SPIRE agent attestation...")
    time.sleep(5)
    _identity.register([])
    typer.echo("\nSetup complete.")


@app.command()
def dirs() -> None:
    """Create required data directories."""
    typer.echo("→ Creating directories...")
    for d in [
        PROJECT_DIR / "spire-agent-certs",
        PROJECT_DIR / "audit-logs",
        PROJECT_DIR / "policy",
    ]:
        d.mkdir(parents=True, exist_ok=True)
    typer.echo("  Done.")


@app.command()
def certs(
    force: bool = typer.Option(False, "--force", help="Regenerate certs even if they already exist."),
) -> None:
    """Generate SPIRE agent certificate (x509pop). Skips if already present."""
    if AGENT_CERT.exists() and not force:
        typer.echo("  Certs already exist — skipping. Use --force to regenerate.")
        return

    typer.echo("→ Generating agent CA and certificate...")
    cert_dir = PROJECT_DIR / "spire-agent-certs"
    cert_dir.mkdir(parents=True, exist_ok=True)

    subprocess.run(["openssl", "genrsa", "-out", str(cert_dir / "agent-ca.key"), "2048"], check=True)
    subprocess.run([
        "openssl", "req", "-x509", "-new", "-nodes",
        "-key", str(cert_dir / "agent-ca.key"),
        "-sha256", "-days", "365",
        "-subj", "/CN=agent-ca",
        "-out", str(cert_dir / "agent-ca.crt"),
    ], check=True)
    subprocess.run(["openssl", "genrsa", "-out", str(AGENT_KEY), "2048"], check=True)
    subprocess.run([
        "openssl", "req", "-new",
        "-key", str(AGENT_KEY),
        "-subj", "/CN=spire-agent",
        "-out", str(cert_dir / "agent.csr"),
    ], check=True)

    ext_file = cert_dir / "agent-ext.cnf"
    ext_file.write_text("[v3_req]\nkeyUsage = critical, digitalSignature\n")

    subprocess.run([
        "openssl", "x509", "-req",
        "-in", str(cert_dir / "agent.csr"),
        "-CA", str(cert_dir / "agent-ca.crt"),
        "-CAkey", str(cert_dir / "agent-ca.key"),
        "-CAcreateserial", "-days", "365", "-sha256",
        "-extfile", str(ext_file), "-extensions", "v3_req",
        "-out", str(AGENT_CERT),
    ], check=True)

    typer.echo(f"  Certs written to {cert_dir}")


@app.command()
def permissions() -> None:
    """Set directory ownership for SPIRE (UID 1000)."""
    import json as _json
    project_name = compose.run("config", "--format", "json", capture=True).stdout
    project = _json.loads(project_name).get("name", PROJECT_DIR.name)

    typer.echo("→ Setting permissions on spire-server-data volume (UID 1000)...")
    subprocess.run([
        "docker", "run", "--rm",
        "-v", f"{project}_spire-server-data:/data",
        "busybox", "chown", "-R", "1000:1000", "/data",
    ], check=True)
    typer.echo("  Done.")


@app.command()
def start() -> None:
    """Start all containers (infrastructure + gateways)."""
    typer.echo("→ Starting containers...")
    compose.run("up", "-d")


@app.command()
def stop() -> None:
    """Stop all containers."""
    typer.echo("→ Stopping containers...")
    compose.run("down")


@app.command()
def restart() -> None:
    """Restart all containers."""
    compose.run("restart")


@app.command()
def status() -> None:
    """Show running container status."""
    compose.run("ps")


@app.command()
def wait() -> None:
    """Wait until the SPIRE server is healthy."""
    typer.echo("→ Waiting for SPIRE server...")
    for i in range(20):
        if spire.is_healthy():
            typer.echo("  SPIRE server is healthy.")
            return
        typer.echo(f"  ...waiting ({i+1}/20)")
        time.sleep(3)
    typer.echo("  SPIRE server did not become healthy in time.", err=True)
    raise typer.Exit(1)

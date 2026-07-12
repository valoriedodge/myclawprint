import subprocess
import time
from pathlib import Path

import typer
from typing import List

from ..utils import compose, spire

app = typer.Typer(help="First-time installation and infrastructure setup.")

PROJECT_DIR = Path(__file__).parent.parent.parent
AGENT_CERT  = PROJECT_DIR / "spire-agent-certs" / "agent.crt.pem"
AGENT_KEY   = PROJECT_DIR / "spire-agent-certs" / "agent.key.pem"
SPIRE_DATA  = PROJECT_DIR / "spire-server-data"


@app.command()
def all(
    skip_onboard: bool = typer.Option(False, "--skip-onboard", help="Skip interactive gateway onboarding."),
) -> None:
    """Full first-time setup: dirs, certs, permissions, onboard, start, register."""
    dirs()
    certs()
    permissions()
    if not skip_onboard:
        _onboard_all()
    start()
    wait()
    typer.echo("\nSetup complete. Run 'myclawprint identity register' to register workloads.")


@app.command()
def dirs() -> None:
    """Create required data and workspace directories."""
    typer.echo("→ Creating directories...")
    for d in [
        PROJECT_DIR / "spire-server-data",
        PROJECT_DIR / "spire-agent-certs",
        PROJECT_DIR / "audit-logs",
        PROJECT_DIR / "policy",
        Path.home() / ".openclaw_docker" / "workspace",
        Path.home() / ".openclaw_docker_2" / "workspace",
        Path.home() / ".openclaw_docker_cli" / "workspace",
    ]:
        d.mkdir(parents=True, exist_ok=True)

    # Fluentd runs as UID 999 and needs write access to audit-logs
    audit_logs = PROJECT_DIR / "audit-logs"
    subprocess.run(["sudo", "chown", "-R", "999:999", str(audit_logs)], check=True)
    audit_logs.chmod(0o755)
    typer.echo("  Done.")


@app.command()
def certs() -> None:
    """Generate SPIRE agent certificate (x509pop). Skips if already present."""
    if AGENT_CERT.exists():
        typer.echo("  Certs already exist — skipping. Run 'myclawprint setup certs --force' to regenerate.")
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
    """Set directory ownership for SPIRE (UID 1000) and Fluentd (UID 999)."""
    audit_logs = PROJECT_DIR / "audit-logs"
    audit_logs.mkdir(parents=True, exist_ok=True)

    typer.echo("→ Setting permissions on spire-server-data (UID 1000)...")
    subprocess.run(["sudo", "chown", "-R", "1000:1000", str(SPIRE_DATA)], check=True)
    SPIRE_DATA.chmod(0o755)

    typer.echo("→ Setting permissions on audit-logs (UID 999 for Fluentd)...")
    subprocess.run(["sudo", "chown", "-R", "999:999", str(audit_logs)], check=True)
    audit_logs.chmod(0o755)

    typer.echo("  Done.")


@app.command()
def start() -> None:
    """Start all containers."""
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


def _onboard_all() -> None:
    services_file = PROJECT_DIR / ".services"
    services = (
        services_file.read_text().split()
        if services_file.exists()
        else ["openclaw-gateway", "openclaw-gateway-2"]
    )
    for svc in services:
        typer.echo(f"\n── Onboarding {svc} ──")
        try:
            compose.run_interactive(svc, "bash", "-c", "openclaw onboard")
        except subprocess.CalledProcessError:
            typer.echo(f"  [warn] Onboarding skipped or failed for {svc}")

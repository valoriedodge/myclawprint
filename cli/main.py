from pathlib import Path

import typer

from .commands import setup, gateway, identity, policy, audit
from . import utils

app = typer.Typer(
    name="myclawprint",
    help="Openclaw infrastructure CLI — manage SPIRE identities, gateways, and OPA policy.",
    no_args_is_help=True,
)

app.add_typer(setup.app,    name="setup",    help="First-time install and infrastructure lifecycle.")
app.add_typer(gateway.app,  name="gateway",  help="Add and manage openclaw gateway containers.")
app.add_typer(identity.app, name="identity", help="Register and inspect SPIRE workload identities.")
app.add_typer(policy.app,   name="policy",   help="Grant and revoke OPA tool permissions.")
app.add_typer(audit.app,    name="audit",    help="Inspect and verify audit log integrity.")


@app.callback()
def main(
    project_dir: Path = typer.Option(
        Path(__file__).parent.parent,
        "--project-dir",
        help="Path to the project root (where docker-compose.yml lives).",
        envvar="CLAWPRINT_PROJECT_DIR",
    ),
) -> None:
    utils.compose.PROJECT_DIR = str(project_dir)

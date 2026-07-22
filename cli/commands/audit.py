from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import List

import typer

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

app = typer.Typer(help="Inspect and verify audit logs.")

PROJECT_DIR = Path(__file__).parent.parent.parent
AUDIT_DIR   = PROJECT_DIR / "audit-logs"
GENESIS_HASH = "0" * 64


def _parse_log_files() -> List[dict]:
    """Read all audit log files and return parsed entries in timestamp order."""
    entries = []
    for log_file in sorted(AUDIT_DIR.glob("audit.jsonl*.log")):
        for line in log_file.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                # Format: timestamp\topenclaw.audit\t{json}
                parts = line.split("\t", 2)
                if len(parts) != 3:
                    continue
                record = json.loads(parts[2])
                record["_file"] = log_file.name
                entries.append(record)
            except (json.JSONDecodeError, IndexError):
                continue
    return entries


def _verify_signature(stored_hash: str, signature_b64: str, cert_pem: str) -> tuple[bool, str]:
    """Verify the ECDSA signature over the stored hash using the embedded SVID cert."""
    if not _CRYPTO_AVAILABLE:
        return False, "cryptography library not installed (pip install cryptography)"
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        pubkey = cert.public_key()
        sig_bytes = base64.b64decode(signature_b64)
        pubkey.verify(sig_bytes, stored_hash.encode(), ec.ECDSA(hashes.SHA256()))  # type: ignore[arg-type]
        return True, ""
    except InvalidSignature:
        return False, "signature does not match"
    except Exception as e:
        return False, str(e)


@app.command()
def verify() -> None:
    """Verify hash chain integrity and ECDSA signatures of all audit logs.

    For each entry:
      - Chain check: previousHash must match the prior entry's hash
      - Signature check: ECDSA signature must verify against the embedded SVID certificate

    Entries without an embedded certificate (written by older plugin versions)
    have their signatures skipped with a warning.
    """
    if not AUDIT_DIR.exists():
        typer.echo("[error] audit-logs/ directory not found.", err=True)
        raise typer.Exit(1)

    entries = _parse_log_files()
    if not entries:
        typer.echo("No audit log entries found.")
        return

    if not _CRYPTO_AVAILABLE:
        typer.echo("[warn] cryptography library not installed — signature verification skipped.")
        typer.echo("       Run: pip install cryptography\n")

    typer.echo(f"Verifying {len(entries)} audit log entries...\n")

    errors = 0
    chains: dict[str, str] = {}

    for i, record in enumerate(entries):
        payload     = record.get("payload", {})
        stored_hash = record.get("hash", "")
        signature   = record.get("signature", "")
        spiffe_id   = payload.get("spiffeId", "unknown")
        sequence    = payload.get("sequence", "?")
        prev_hash   = payload.get("previousHash", "")
        tool        = payload.get("toolName", "?")
        cert_pem    = payload.get("svid_cert")

        label = f"entry {i} (seq={sequence}, tool={tool}, spiffeId={spiffe_id})"
        entry_ok = True

        # --- Chain check ---
        if sequence == 0:
            if prev_hash != GENESIS_HASH:
                typer.echo(f"  [FAIL] {label}", err=True)
                typer.echo(f"           chain: seq=0 but previousHash is not the genesis hash", err=True)
                entry_ok = False
                errors += 1
        else:
            expected = chains.get(spiffe_id)
            if expected is None:
                typer.echo(f"  [warn] {label} — first entry seen mid-sequence, chain link unverifiable")
            elif prev_hash != expected:
                typer.echo(f"  [FAIL] {label}", err=True)
                typer.echo(f"           chain: previousHash does not match prior entry's hash", err=True)
                typer.echo(f"           expected: {expected[:32]}...", err=True)
                typer.echo(f"           got:      {prev_hash[:32]}...", err=True)
                entry_ok = False
                errors += 1

        # --- Signature check ---
        if cert_pem and signature and _CRYPTO_AVAILABLE:
            sig_ok, sig_err = _verify_signature(stored_hash, signature, cert_pem)
            if not sig_ok:
                typer.echo(f"  [FAIL] {label}", err=True)
                typer.echo(f"           signature: {sig_err}", err=True)
                entry_ok = False
                errors += 1
        elif not cert_pem:
            if entry_ok:
                typer.echo(f"  [warn] {label} — no svid_cert in entry, signature not verified (older log)")
            entry_ok = False  # don't print [ok] for unsigned entries

        if entry_ok:
            typer.echo(f"  [ok]   {label}")

        chains[spiffe_id] = stored_hash

    typer.echo()
    if errors:
        typer.echo(f"[FAIL] {errors} integrity error(s) found.", err=True)
        raise typer.Exit(1)
    else:
        typer.echo(f"[ok] All {len(entries)} entries passed integrity check.")


@app.command(name="list")
def list_entries(
    spiffe_id: str = typer.Option(None, "--spiffe-id", help="Filter by SPIFFE ID."),
    tool: str      = typer.Option(None, "--tool", help="Filter by tool name."),
    denied: bool   = typer.Option(False, "--denied", help="Show only denied tool calls."),
    n: int         = typer.Option(0, "--last", help="Show only the last N entries."),
) -> None:
    """List audit log entries with optional filters."""
    if not AUDIT_DIR.exists():
        typer.echo("[error] audit-logs/ directory not found.", err=True)
        raise typer.Exit(1)

    entries = _parse_log_files()
    if not entries:
        typer.echo("No audit log entries found.")
        return

    # Apply filters
    if spiffe_id:
        entries = [e for e in entries if e.get("payload", {}).get("spiffeId", "") == spiffe_id]
    if tool:
        entries = [e for e in entries if e.get("payload", {}).get("toolName", "") == tool]
    if denied:
        entries = [e for e in entries if not e.get("payload", {}).get("opaDecision", True)]
    if n:
        entries = entries[-n:]

    if not entries:
        typer.echo("No matching entries.")
        return

    for record in entries:
        payload   = record.get("payload", {})
        allowed   = payload.get("opaDecision", False)
        status    = "allow" if allowed else "deny "
        timestamp = payload.get("timestamp", "")
        spiffe    = payload.get("spiffeId", "?")
        tool_name = payload.get("toolName", "?")
        seq       = payload.get("sequence", "?")
        typer.echo(f"  [{status}] seq={seq} tool={tool_name} spiffeId={spiffe} ts={timestamp}")

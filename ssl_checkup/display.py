from typing import Optional

"""Certificate display and pretty printing."""

import sys
from datetime import datetime
from typing import Any, Dict

from .formatting import OutputFormatter
from .parser import get_issuer_org, get_subject_cn, parse_pem_cert, parse_san


def pretty_print_cert(
    cert: Dict[str, Any],
    hostname: str,
    port: int,
    days_to_warn: int,
    color_output: bool,
    pem_cert: Optional[str] = None,
    insecure: bool = False,
) -> None:
    """
    Pretty print certificate information with color formatting.

    Args:
        cert: Certificate dictionary
        hostname: Target hostname
        port: Target port
        days_to_warn: Days threshold for warning status
        color_output: Whether to use color formatting
        pem_cert: PEM certificate string (for fallback parsing)
        insecure: Whether insecure mode is enabled
    """
    formatter = OutputFormatter(color_output)

    not_after = cert.get("notAfter")
    not_before = cert.get("notBefore")

    # If cert is empty (due to --insecure) and we have PEM, try to parse it
    if not_after is None and insecure and pem_cert:
        parsed_cert = parse_pem_cert(pem_cert)
        if parsed_cert:
            cert = parsed_cert
            not_after = cert.get("notAfter")
            not_before = cert.get("notBefore")

    if not_after is None:
        _handle_missing_cert_data(insecure, cert)
        return

    # Parse expiration and calculate status
    expire_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    now = datetime.utcnow()
    days_left = (expire_date - now).days

    # Get certificate details
    issuer_val = get_issuer_org(cert) or "N/A"
    subject_val = get_subject_cn(cert) or "N/A"
    san = parse_san(cert)

    # Determine highlighting
    query = hostname.lower()
    subject_match = subject_val.lower() == query

    # Format status
    status = formatter.format_status(days_left)

    # Print certificate information
    print(
        f"\n{formatter.cfield('Certificate for:')} "
        f"{formatter.cquery(f'{hostname}:{port}')}"
    )
    print(f"  {formatter.cfield('Status:')} {status}")
    print(
        f"  {formatter.cfield('Not Before:')} "
        f"{formatter.cplain(not_before or 'N/A')}"
    )
    print(
        f"  {formatter.cfield('Not After:')}  "
        f"{formatter.cplain(not_after or 'N/A')}"
    )
    print(f"  {formatter.cfield('Issuer:')}     " f"{formatter.cissuer(issuer_val)}")
    print(
        f"  {formatter.cfield('Subject:')}    "
        f"{formatter.csubject(subject_val, highlight=subject_match)}"
    )

    if san:
        print(f"  {formatter.cfield('SANs:')}")
        for name in san:
            highlight = name.lower() == query or (
                subject_match and name.lower() == subject_val.lower()
            )
            print(f"    - {formatter.csan(name, highlight=highlight)}")
    print()


def _handle_missing_cert_data(insecure: bool, cert: Dict[str, Any]) -> None:
    """Handle cases where certificate data is missing or incomplete."""
    from .parser import CRYPTOGRAPHY_AVAILABLE

    if insecure and not CRYPTOGRAPHY_AVAILABLE:
        print(
            "Warning: Certificate details are limited when using --insecure/-k. "
            "Install 'cryptography' for full details:",
            file=sys.stderr,
        )
        print("  pip install cryptography", file=sys.stderr)
    else:
        print(
            "Error: Could not retrieve certificate expiration "
            "date (notAfter is missing). "
            "This can happen when using --insecure/-k on some servers.",
            file=sys.stderr,
        )
    print("Raw certificate:", cert, file=sys.stderr)

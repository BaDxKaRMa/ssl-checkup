"""SSL certificate retrieval and connection handling."""

import socket
import ssl
from typing import Any, Dict, Union


def get_certificate(
    hostname: str, port: int, pem: bool = False, insecure: bool = False
) -> Union[str, Dict[str, Any]]:
    """
    Retrieve SSL certificate from a remote server.

    Args:
        hostname: The hostname to connect to
        port: The port to connect to
        pem: If True, return only the PEM certificate string
        insecure: If True, bypass certificate validation

    Returns:
        If pem=True: PEM certificate string or empty string if not available
        If pem=False: Dictionary with certificate info and connection details
    """
    if insecure:
        context = ssl._create_unverified_context()  # nosec B323
    else:
        context = ssl.create_default_context()

    with socket.create_connection((hostname, port), timeout=10) as sock:
        resolved_ip = sock.getpeername()[0]
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            tls_version = ssock.version()
            cipher = ssock.cipher()
            der_cert = ssock.getpeercert(binary_form=True)
            pem_cert = ssl.DER_cert_to_PEM_cert(der_cert) if der_cert else ""
            cert = ssock.getpeercert()

            if pem:
                return pem_cert or ""

            return {
                "cert": cert,
                "pem": pem_cert,
                "resolved_ip": resolved_ip,
                "tls_version": tls_version,
                "cipher": cipher,
            }

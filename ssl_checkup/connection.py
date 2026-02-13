"""SSL certificate retrieval and connection handling."""

import socket
import ssl
from typing import Any, Dict, Union


def _create_connection(
    hostname: str, port: int, timeout: float, ip_version: str
) -> socket.socket:
    """Create a TCP socket with optional IP family pinning."""
    if ip_version == "auto":
        return socket.create_connection((hostname, port), timeout=timeout)

    family = socket.AF_INET if ip_version == "4" else socket.AF_INET6
    addr_info = socket.getaddrinfo(
        hostname,
        port,
        family=family,
        type=socket.SOCK_STREAM,
    )

    last_error: OSError | None = None
    for af, socktype, proto, _, sockaddr in addr_info:
        sock = socket.socket(af, socktype, proto)
        try:
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()

    if last_error is not None:
        raise last_error
    raise socket.gaierror(f"No {ip_version} records found for {hostname}")


def get_certificate(
    hostname: str,
    port: int,
    pem: bool = False,
    insecure: bool = False,
    timeout: float = 10.0,
    ip_version: str = "auto",
    include_chain: bool = False,
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

    with _create_connection(
        hostname, port, timeout=timeout, ip_version=ip_version
    ) as sock:
        resolved_ip = sock.getpeername()[0]
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            tls_version = ssock.version()
            cipher = ssock.cipher()
            der_cert = ssock.getpeercert(binary_form=True)
            pem_cert = ssl.DER_cert_to_PEM_cert(der_cert) if der_cert else ""
            cert = ssock.getpeercert()
            chain_pem: list[str] = []
            chain_source: str | None = None

            if include_chain:
                try:
                    chain_der: list[bytes] = []
                    if not insecure and hasattr(ssock, "get_verified_chain"):
                        verified_chain = ssock.get_verified_chain()
                        chain_der = (
                            [
                                der
                                for der in verified_chain
                                if isinstance(der, (bytes, bytearray))
                            ]
                            if verified_chain
                            else []
                        )
                        chain_source = "verified"
                    elif hasattr(ssock, "get_unverified_chain"):
                        unverified_chain = ssock.get_unverified_chain()
                        chain_der = (
                            [
                                der
                                for der in unverified_chain
                                if isinstance(der, (bytes, bytearray))
                            ]
                            if unverified_chain
                            else []
                        )
                        chain_source = "unverified"

                    chain_pem = [ssl.DER_cert_to_PEM_cert(der) for der in chain_der]
                except Exception:  # nosec B110
                    chain_pem = []

                if not chain_pem and pem_cert:
                    chain_pem = [pem_cert]
                    chain_source = chain_source or "leaf-only"

            if pem:
                return pem_cert or ""

            return {
                "cert": cert,
                "pem": pem_cert,
                "resolved_ip": resolved_ip,
                "tls_version": tls_version,
                "cipher": cipher,
                "chain_pem": chain_pem,
                "chain_source": chain_source,
            }

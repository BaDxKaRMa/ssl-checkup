from typing import List, Optional

"""Certificate parsing and data extraction utilities."""

from typing import Any, Dict

# Handle optional cryptography dependency
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    x509 = None  # type: ignore
    default_backend = None  # type: ignore


def parse_san(cert: Dict[str, Any]) -> List[str]:
    """
    Extract Subject Alternative Names from certificate.

    Args:
        cert: Certificate dictionary from SSL socket

    Returns:
        List of DNS names from SAN extension
    """
    san = []
    for ext in cert.get("subjectAltName", []):
        if ext[0] == "DNS":
            san.append(ext[1])
    return san


def extract_cert_field(
    cert: Dict[str, Any], field_type: str, field_names: List[str]
) -> Optional[str]:
    """
    Extract a specific field from certificate subject or issuer.

    Args:
        cert: Certificate dictionary
        field_type: 'subject' or 'issuer'
        field_names: List of possible field names to look for

    Returns:
        The field value if found, otherwise None
    """
    field_data = cert.get(field_type, [])
    try:
        for tup in field_data:
            try:
                for k, v in tup:
                    if k in field_names:
                        return v
            except (ValueError, TypeError):
                # Skip malformed tuples
                continue
    except TypeError:
        # field_data is not iterable
        return None
    return None


def get_subject_cn(cert: Dict[str, Any]) -> Optional[str]:
    """Get Common Name from certificate subject."""
    return extract_cert_field(cert, "subject", ["commonName", "CN"])


def get_issuer_org(cert: Dict[str, Any]) -> Optional[str]:
    """Get Organization from certificate issuer."""
    return extract_cert_field(cert, "issuer", ["organizationName", "O"])


def parse_pem_cert(pem_cert: Optional[str]) -> Optional[Dict[str, Any]]:
    """
    Parse certificate details from PEM when standard parsing fails.

    This is useful when using --insecure flag where standard cert parsing
    may not work properly.

    Args:
        pem_cert: PEM certificate string

    Returns:
        Certificate dictionary compatible with pretty_print_cert, or
        None if parsing fails
    """
    if (
        not CRYPTOGRAPHY_AVAILABLE
        or not pem_cert
        or x509 is None
        or default_backend is None
    ):
        return None

    try:
        cert = x509.load_pem_x509_certificate(pem_cert.encode(), default_backend())

        # Extract basic info
        subject_attrs = {}
        for attr in cert.subject:
            subject_attrs[attr.oid._name] = attr.value

        issuer_attrs = {}
        for attr in cert.issuer:
            issuer_attrs[attr.oid._name] = attr.value

        # Extract SANs
        san_list = []
        try:
            from cryptography.x509.oid import ExtensionOID

            san_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            # Extract DNS names from SAN extension value
            # Use hasattr to check for get_values_for_type method
            if hasattr(san_ext.value, "get_values_for_type"):
                try:
                    dns_names = san_ext.value.get_values_for_type(  # type: ignore[attr-defined] # noqa: E501
                        x509.DNSName
                    )
                    san_list.extend(dns_names)
                except (AttributeError, TypeError):
                    # Fallback for different cryptography versions
                    pass
        except (x509.ExtensionNotFound, AttributeError, ImportError):
            pass
        except Exception:  # nosec B110
            pass

        # Convert to format compatible with pretty_print_cert
        return {
            "notAfter": cert.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT"),
            "notBefore": cert.not_valid_before_utc.strftime("%b %d %H:%M:%S %Y GMT"),
            "subject": [[(k, v)] for k, v in subject_attrs.items()],
            "issuer": [[(k, v)] for k, v in issuer_attrs.items()],
            "subjectAltName": [("DNS", name) for name in san_list],
        }
    except Exception:
        return None

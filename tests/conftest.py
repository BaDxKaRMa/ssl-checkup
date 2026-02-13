"""Test configuration and fixtures."""

from datetime import datetime, timedelta
from typing import Any, Dict

import pytest


@pytest.fixture
def sample_cert() -> Dict[str, Any]:
    """Sample certificate data for testing."""
    future_date = datetime.utcnow() + timedelta(days=90)
    past_date = datetime.utcnow() - timedelta(days=30)

    return {
        "notAfter": future_date.strftime("%b %d %H:%M:%S %Y GMT"),
        "notBefore": past_date.strftime("%b %d %H:%M:%S %Y GMT"),
        "subject": [
            [("countryName", "US")],
            [("organizationName", "Example Corp")],
            [("commonName", "example.com")],
        ],
        "issuer": [
            [("countryName", "US")],
            [("organizationName", "Let's Encrypt")],
            [("commonName", "R3")],
        ],
        "subjectAltName": [
            ("DNS", "example.com"),
            ("DNS", "www.example.com"),
            ("DNS", "api.example.com"),
        ],
    }


@pytest.fixture
def expired_cert() -> Dict[str, Any]:
    """Expired certificate data for testing."""
    past_date = datetime.utcnow() - timedelta(days=30)
    very_past_date = datetime.utcnow() - timedelta(days=365)

    return {
        "notAfter": past_date.strftime("%b %d %H:%M:%S %Y GMT"),
        "notBefore": very_past_date.strftime("%b %d %H:%M:%S %Y GMT"),
        "subject": [[("commonName", "expired.example.com")]],
        "issuer": [[("organizationName", "Example CA")]],
        "subjectAltName": [("DNS", "expired.example.com")],
    }


@pytest.fixture
def soon_expiring_cert() -> Dict[str, Any]:
    """Certificate expiring soon for testing."""
    soon_date = datetime.utcnow() + timedelta(days=15)
    past_date = datetime.utcnow() - timedelta(days=30)

    return {
        "notAfter": soon_date.strftime("%b %d %H:%M:%S %Y GMT"),
        "notBefore": past_date.strftime("%b %d %H:%M:%S %Y GMT"),
        "subject": [[("commonName", "warning.example.com")]],
        "issuer": [[("organizationName", "Example CA")]],
        "subjectAltName": [("DNS", "warning.example.com")],
    }


@pytest.fixture
def sample_pem_cert() -> str:
    """Sample PEM certificate for testing."""
    return """-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo0IwQDAPBgNVHRMBAf8E
BTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUhBjMhTTsvAyUlC4IWZzH
shBOCggwDQYJKoZIhvcNAQEFBQADggEBAED3F/S/mfkCVRK4K6R3YSX1UDzZJLgT
/SqJiNhGBQhjCgxXZj5IZ+Fd7FSDd2Q3p8kRfUOUOLtG7iFf7pJpjGEUcFB9f9OM
/DoBKo1BVj8MX+S42EAEEJbw8+xrUjTv8C+L5JLxJMLY9WcOSGU5lQXg8/W7VN7x
U0Nrjo9xVEQCJgd6xAGLKOvEOvY7YLzq+IuWL+Y0zf8nLO7z2qQOQVJ++kLqH/oF
rKk7mAHXBvf/PcWaGSU9OO6K8H5n3EHhH6JqVGAc+H7XMc4N5o0NX/nT4GjJ1HS9
JQ7xXI8JQd8BFNFG4l7+3t3qQZ8YGJr0n8aHX8i6mB3YfPg+N+LQPJ8=
-----END CERTIFICATE-----"""


@pytest.fixture
def mock_cert_info() -> Dict[str, Any]:
    """Mock certificate info from connection."""
    future_date = datetime.utcnow() + timedelta(days=90)
    past_date = datetime.utcnow() - timedelta(days=30)

    return {
        "cert": {
            "notAfter": future_date.strftime("%b %d %H:%M:%S %Y GMT"),
            "notBefore": past_date.strftime("%b %d %H:%M:%S %Y GMT"),
            "subject": [[("commonName", "example.com")]],
            "issuer": [[("organizationName", "Example CA")]],
            "subjectAltName": [("DNS", "example.com"), ("DNS", "www.example.com")],
        },
        "pem": "-----BEGIN CERTIFICATE-----\nMOCK_CERT_DATA\n-----END CERTIFICATE-----",
        "resolved_ip": "93.184.216.34",
        "tls_version": "TLSv1.3",
        "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
    }

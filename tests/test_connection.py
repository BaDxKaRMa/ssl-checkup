"""Tests for connection module."""

import socket
import ssl
from unittest.mock import MagicMock, Mock, patch

import pytest

from ssl_checkup.connection import get_certificate


class TestGetCertificate:
    """Test SSL certificate retrieval."""

    @patch("ssl_checkup.connection.socket.create_connection")
    @patch("ssl_checkup.connection.ssl.create_default_context")
    def test_get_certificate_success(self, mock_context, mock_socket):
        """Test successful certificate retrieval."""
        # Mock socket connection
        mock_sock = Mock()
        mock_sock.getpeername.return_value = ("192.168.1.1", 443)
        mock_socket.return_value.__enter__.return_value = mock_sock

        # Mock SSL socket
        mock_ssl_sock = Mock()
        mock_ssl_sock.version.return_value = "TLSv1.3"
        mock_ssl_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssl_sock.getpeercert.side_effect = [
            b"mock_der_cert",  # binary_form=True
            {"subject": [["commonName", "example.com"]]},  # binary_form=False (default)
        ]

        # Mock SSL context
        mock_ssl_context = Mock()
        mock_ssl_context.wrap_socket.return_value = MagicMock()
        mock_ssl_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock
        mock_context.return_value = mock_ssl_context

        # Mock PEM conversion
        with patch("ssl_checkup.connection.ssl.DER_cert_to_PEM_cert") as mock_pem:
            mock_pem.return_value = (
                "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----"
            )

            result = get_certificate("example.com", 443)

            assert isinstance(result, dict)
            assert "cert" in result
            assert "pem" in result
            assert "resolved_ip" in result
            assert "tls_version" in result
            assert "cipher" in result
            assert result["resolved_ip"] == "192.168.1.1"
            assert result["tls_version"] == "TLSv1.3"

    @patch("ssl_checkup.connection.socket.create_connection")
    @patch("ssl_checkup.connection.ssl.create_default_context")
    def test_get_certificate_pem_only(self, mock_context, mock_socket):
        """Test certificate retrieval with PEM output only."""
        # Setup mocks similar to above
        mock_sock = Mock()
        mock_sock.getpeername.return_value = ("192.168.1.1", 443)
        mock_socket.return_value.__enter__.return_value = mock_sock

        mock_ssl_sock = Mock()
        mock_ssl_sock.getpeercert.return_value = b"mock_der_cert"

        mock_ssl_context = Mock()
        mock_ssl_context.wrap_socket.return_value = MagicMock()
        mock_ssl_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock
        mock_context.return_value = mock_ssl_context

        pem_cert = "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----"
        with patch("ssl_checkup.connection.ssl.DER_cert_to_PEM_cert") as mock_pem:
            mock_pem.return_value = pem_cert

            result = get_certificate("example.com", 443, pem=True)

            assert result == pem_cert

    @patch("ssl_checkup.connection.socket.create_connection")
    @patch("ssl_checkup.connection.ssl._create_unverified_context")
    def test_get_certificate_insecure(self, mock_unverified_context, mock_socket):
        """Test certificate retrieval with insecure mode."""
        # Setup mocks
        mock_sock = Mock()
        mock_sock.getpeername.return_value = ("192.168.1.1", 443)
        mock_socket.return_value.__enter__.return_value = mock_sock

        mock_ssl_sock = Mock()
        mock_ssl_sock.version.return_value = "TLSv1.2"
        mock_ssl_sock.cipher.return_value = (
            "ECDHE-RSA-AES256-GCM-SHA384",
            "TLSv1.2",
            256,
        )
        mock_ssl_sock.getpeercert.side_effect = [
            b"mock_der_cert",
            {"subject": [["commonName", "example.com"]]},
        ]

        mock_ssl_context = Mock()
        mock_ssl_context.wrap_socket.return_value = MagicMock()
        mock_ssl_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock
        mock_unverified_context.return_value = mock_ssl_context

        with patch("ssl_checkup.connection.ssl.DER_cert_to_PEM_cert") as mock_pem:
            mock_pem.return_value = (
                "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----"
            )

            result = get_certificate("example.com", 443, insecure=True)

            assert isinstance(result, dict)
            mock_unverified_context.assert_called_once()

    @patch("ssl_checkup.connection.socket.create_connection")
    def test_get_certificate_connection_timeout(self, mock_socket):
        """Test certificate retrieval with connection timeout."""
        mock_socket.side_effect = socket.timeout("Connection timed out")

        with pytest.raises(socket.timeout):
            get_certificate("example.com", 443)

    @patch("ssl_checkup.connection.socket.create_connection")
    def test_get_certificate_connection_refused(self, mock_socket):
        """Test certificate retrieval with connection refused."""
        mock_socket.side_effect = ConnectionRefusedError("Connection refused")

        with pytest.raises(ConnectionRefusedError):
            get_certificate("example.com", 443)

    @patch("ssl_checkup.connection.socket.create_connection")
    @patch("ssl_checkup.connection.ssl.create_default_context")
    def test_get_certificate_ssl_error(self, mock_context, mock_socket):
        """Test certificate retrieval with SSL error."""
        mock_sock = Mock()
        mock_sock.getpeername.return_value = ("192.168.1.1", 443)
        mock_socket.return_value.__enter__.return_value = mock_sock

        mock_ssl_context = Mock()
        mock_ssl_context.wrap_socket.side_effect = ssl.SSLError("SSL handshake failed")
        mock_context.return_value = mock_ssl_context

        with pytest.raises(ssl.SSLError):
            get_certificate("example.com", 443)

    @patch("ssl_checkup.connection.socket.create_connection")
    @patch("ssl_checkup.connection.ssl.create_default_context")
    def test_get_certificate_no_der_cert(self, mock_context, mock_socket):
        """Test certificate retrieval when no DER certificate is available."""
        mock_sock = Mock()
        mock_sock.getpeername.return_value = ("192.168.1.1", 443)
        mock_socket.return_value.__enter__.return_value = mock_sock

        mock_ssl_sock = Mock()
        mock_ssl_sock.version.return_value = "TLSv1.3"
        mock_ssl_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssl_sock.getpeercert.side_effect = [
            None,  # binary_form=True returns None
            {"subject": [["commonName", "example.com"]]},  # binary_form=False
        ]

        mock_ssl_context = Mock()
        mock_ssl_context.wrap_socket.return_value = MagicMock()
        mock_ssl_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock
        mock_context.return_value = mock_ssl_context

        result = get_certificate("example.com", 443)

        assert isinstance(result, dict)
        assert result["pem"] == ""  # Empty PEM when no DER cert

    @patch("ssl_checkup.connection.socket.create_connection")
    @patch("ssl_checkup.connection.ssl.create_default_context")
    def test_get_certificate_custom_port(self, mock_context, mock_socket):
        """Test certificate retrieval on custom port."""
        mock_sock = Mock()
        mock_sock.getpeername.return_value = ("192.168.1.1", 8443)
        mock_socket.return_value.__enter__.return_value = mock_sock

        mock_ssl_sock = Mock()
        mock_ssl_sock.version.return_value = "TLSv1.3"
        mock_ssl_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssl_sock.getpeercert.side_effect = [
            b"mock_der_cert",
            {"subject": [["commonName", "example.com"]]},
        ]

        mock_ssl_context = Mock()
        mock_ssl_context.wrap_socket.return_value = MagicMock()
        mock_ssl_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock
        mock_context.return_value = mock_ssl_context

        with patch("ssl_checkup.connection.ssl.DER_cert_to_PEM_cert") as mock_pem:
            mock_pem.return_value = (
                "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----"
            )

            result = get_certificate("example.com", 8443)

            assert isinstance(result, dict)
            mock_socket.assert_called_with(("example.com", 8443), timeout=10)

    def test_get_certificate_invalid_hostname(self):
        """Test certificate retrieval with invalid hostname."""
        with pytest.raises(socket.gaierror):
            get_certificate("invalid.hostname.that.does.not.exist", 443)

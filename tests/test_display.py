"""Tests for display module."""

from io import StringIO
from unittest.mock import patch

from ssl_checkup.display import _handle_missing_cert_data, pretty_print_cert


class TestPrettyPrintCert:
    """Test certificate display functionality."""

    @patch("sys.stdout", new_callable=StringIO)
    def test_pretty_print_cert_valid(self, mock_stdout, sample_cert):
        """Test pretty printing a valid certificate."""
        pretty_print_cert(
            sample_cert,
            "example.com",
            443,
            30,
            True,  # color_output
            None,
            False,  # insecure
        )

        output = mock_stdout.getvalue()

        assert "Certificate for: example.com:443" in output
        assert "Status:" in output
        assert "VALID" in output
        assert "Not Before:" in output
        assert "Not After:" in output
        assert "Issuer:" in output
        assert "Let's Encrypt" in output
        assert "Subject:" in output
        assert "example.com" in output
        assert "SANs:" in output
        assert "www.example.com" in output
        assert "api.example.com" in output

    @patch("sys.stdout", new_callable=StringIO)
    def test_pretty_print_cert_expired(self, mock_stdout, expired_cert):
        """Test pretty printing an expired certificate."""
        pretty_print_cert(
            expired_cert,
            "expired.example.com",
            443,
            30,
            True,  # color_output
            None,
            False,  # insecure
        )

        output = mock_stdout.getvalue()

        assert "Certificate for: expired.example.com:443" in output
        assert "Status:" in output
        assert "EXPIRED" in output

    @patch("sys.stdout", new_callable=StringIO)
    def test_pretty_print_cert_warning(self, mock_stdout, soon_expiring_cert):
        """Test pretty printing a certificate expiring soon."""
        pretty_print_cert(
            soon_expiring_cert,
            "warning.example.com",
            443,
            30,
            True,  # color_output
            None,
            False,  # insecure
        )

        output = mock_stdout.getvalue()

        assert "Certificate for: warning.example.com:443" in output
        assert "Status:" in output
        assert "WARNING" in output
        assert "days left" in output

    @patch("sys.stdout", new_callable=StringIO)
    def test_pretty_print_cert_no_color(self, mock_stdout, sample_cert):
        """Test pretty printing without color output."""
        pretty_print_cert(
            sample_cert,
            "example.com",
            443,
            30,
            False,  # color_output
            None,
            False,  # insecure
        )

        output = mock_stdout.getvalue()

        assert "Certificate for: example.com:443" in output
        assert "Status:" in output
        assert "VALID" in output

    @patch("sys.stdout", new_callable=StringIO)
    def test_pretty_print_cert_custom_port(self, mock_stdout, sample_cert):
        """Test pretty printing with custom port."""
        pretty_print_cert(
            sample_cert,
            "example.com",
            8443,
            30,
            True,  # color_output
            None,
            False,  # insecure
        )

        output = mock_stdout.getvalue()

        assert "Certificate for: example.com:8443" in output

    @patch("sys.stdout", new_callable=StringIO)
    def test_pretty_print_cert_no_san(self, mock_stdout):
        """Test pretty printing certificate without SAN."""
        cert = {
            "notAfter": "Dec 15 23:59:59 2025 GMT",
            "notBefore": "Sep 15 00:00:00 2024 GMT",
            "subject": [[("commonName", "example.com")]],
            "issuer": [[("organizationName", "Example CA")]],
            "subjectAltName": [],
        }

        pretty_print_cert(
            cert, "example.com", 443, 30, True, None, False  # color_output  # insecure
        )

        output = mock_stdout.getvalue()

        assert "Certificate for: example.com:443" in output
        assert "Subject:" in output
        assert "SANs:" not in output

    @patch("ssl_checkup.display.parse_pem_cert")
    @patch("sys.stdout", new_callable=StringIO)
    def test_pretty_print_cert_insecure_with_pem(self, mock_stdout, mock_parse_pem):
        """Test pretty printing with insecure flag and PEM fallback."""
        # Empty cert (typical for --insecure)
        empty_cert = {"notAfter": None}

        # Mock parsed PEM cert
        parsed_cert = {
            "notAfter": "Dec 15 23:59:59 2025 GMT",
            "notBefore": "Sep 15 00:00:00 2024 GMT",
            "subject": [[("commonName", "example.com")]],
            "issuer": [[("organizationName", "Example CA")]],
            "subjectAltName": [("DNS", "example.com")],
        }

        mock_parse_pem.return_value = parsed_cert

        pretty_print_cert(
            empty_cert,
            "example.com",
            443,
            30,
            True,  # color_output
            "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----",
            True,  # insecure
        )

        output = mock_stdout.getvalue()

        assert "Certificate for: example.com:443" in output
        assert "Status:" in output
        assert "VALID" in output
        mock_parse_pem.assert_called_once()

    @patch("ssl_checkup.display._handle_missing_cert_data")
    def test_pretty_print_cert_missing_data(self, mock_handle_missing):
        """Test pretty printing with missing certificate data."""
        empty_cert = {"notAfter": None}

        pretty_print_cert(
            empty_cert,
            "example.com",
            443,
            30,
            True,  # color_output
            None,
            False,  # insecure
        )

        mock_handle_missing.assert_called_once_with(False, empty_cert)

    @patch("sys.stdout", new_callable=StringIO)
    def test_pretty_print_cert_subject_highlighting(self, mock_stdout):
        """Test subject highlighting when it matches the hostname."""
        cert = {
            "notAfter": "Dec 15 23:59:59 2025 GMT",
            "notBefore": "Sep 15 00:00:00 2024 GMT",
            "subject": [[("commonName", "example.com")]],
            "issuer": [[("organizationName", "Example CA")]],
            "subjectAltName": [("DNS", "example.com"), ("DNS", "www.example.com")],
        }

        pretty_print_cert(
            cert, "example.com", 443, 30, True, None, False  # color_output  # insecure
        )

        output = mock_stdout.getvalue()

        assert "Certificate for: example.com:443" in output
        assert "Subject:" in output
        assert "example.com" in output

    @patch("sys.stdout", new_callable=StringIO)
    def test_pretty_print_cert_san_highlighting(self, mock_stdout):
        """Test SAN highlighting when it matches the hostname."""
        cert = {
            "notAfter": "Dec 15 23:59:59 2025 GMT",
            "notBefore": "Sep 15 00:00:00 2024 GMT",
            "subject": [[("commonName", "different.com")]],
            "issuer": [[("organizationName", "Example CA")]],
            "subjectAltName": [("DNS", "example.com"), ("DNS", "www.example.com")],
        }

        pretty_print_cert(
            cert, "example.com", 443, 30, True, None, False  # color_output  # insecure
        )

        output = mock_stdout.getvalue()

        assert "Certificate for: example.com:443" in output
        assert "SANs:" in output
        assert "example.com" in output
        assert "www.example.com" in output


class TestHandleMissingCertData:
    """Test missing certificate data handling."""

    @patch("ssl_checkup.parser.CRYPTOGRAPHY_AVAILABLE", False)
    @patch("sys.stderr", new_callable=StringIO)
    def test_handle_missing_cert_data_no_cryptography(self, mock_stderr):
        """Test handling missing cert data when cryptography is not available."""
        cert = {}

        _handle_missing_cert_data(True, cert)

        error_output = mock_stderr.getvalue()

        assert (
            "Warning: Certificate details are limited when using --insecure"
            in error_output
        )
        assert "pip install cryptography" in error_output
        assert "Raw certificate:" in error_output

    @patch("ssl_checkup.parser.CRYPTOGRAPHY_AVAILABLE", True)
    @patch("sys.stderr", new_callable=StringIO)
    def test_handle_missing_cert_data_with_cryptography(self, mock_stderr):
        """Test handling missing cert data when cryptography is available."""
        cert = {}

        _handle_missing_cert_data(True, cert)

        error_output = mock_stderr.getvalue()

        assert "Error: Could not retrieve certificate expiration date" in error_output
        assert "Raw certificate:" in error_output

    @patch("ssl_checkup.parser.CRYPTOGRAPHY_AVAILABLE", True)
    @patch("sys.stderr", new_callable=StringIO)
    def test_handle_missing_cert_data_not_insecure(self, mock_stderr):
        """Test handling missing cert data when not in insecure mode."""
        cert = {}

        _handle_missing_cert_data(False, cert)

        error_output = mock_stderr.getvalue()

        assert "Error: Could not retrieve certificate expiration date" in error_output
        assert "Raw certificate:" in error_output

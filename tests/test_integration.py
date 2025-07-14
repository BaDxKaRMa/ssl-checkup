"""Integration tests for ssl-checkup package."""

import subprocess
import sys
from unittest.mock import patch

import pytest


class TestCliIntegration:
    """Integration tests for the CLI interface."""

    def test_help_command(self):
        """Test that help command works."""
        result = subprocess.run(
            [sys.executable, "-m", "ssl_checkup.main", "--help"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "Check and display SSL certificate details" in result.stdout
        assert "website" in result.stdout
        assert "--insecure" in result.stdout

    def test_version_command(self):
        """Test that version command works."""
        result = subprocess.run(
            [sys.executable, "-m", "ssl_checkup.main", "--version"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "ssl-checkup version" in result.stdout

    def test_no_arguments(self):
        """Test behavior when no arguments are provided."""
        result = subprocess.run(
            [sys.executable, "-m", "ssl_checkup.main"], capture_output=True, text=True
        )

        assert result.returncode == 1
        assert "usage:" in result.stderr or "usage:" in result.stdout

    @pytest.mark.integration
    @patch("ssl_checkup.connection.get_certificate")
    def test_basic_certificate_check(self, mock_get_cert):
        """Test basic certificate checking functionality."""
        # Mock certificate data
        mock_cert = {
            "notAfter": "Dec 15 23:59:59 2024 GMT",
            "notBefore": "Sep 15 00:00:00 2024 GMT",
            "subject": [[("commonName", "example.com")]],
            "issuer": [[("organizationName", "Example CA")]],
            "subjectAltName": [("DNS", "example.com")],
        }

        mock_get_cert.return_value = {"cert": mock_cert}

        result = subprocess.run(
            [sys.executable, "-m", "ssl_checkup.main", "example.com"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "Certificate for:" in result.stdout
        assert "example.com" in result.stdout

    @pytest.mark.integration
    @patch("ssl_checkup.connection.get_certificate")
    def test_print_cert_flag(self, mock_get_cert):
        """Test print certificate flag."""
        mock_pem = (
            "-----BEGIN CERTIFICATE-----\nMOCK_CERT_DATA\n-----END CERTIFICATE-----"
        )
        mock_get_cert.return_value = mock_pem

        result = subprocess.run(
            [sys.executable, "-m", "ssl_checkup.main", "example.com", "--print-cert"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "BEGIN CERTIFICATE" in result.stdout
        assert "END CERTIFICATE" in result.stdout

    @pytest.mark.integration
    def test_issuer_flag(self):
        """Test issuer flag."""
        result = subprocess.run(
            [sys.executable, "-m", "ssl_checkup.main", "example.com", "--issuer"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        # Check that some issuer information is present (real certificate may change)
        assert len(result.stdout.strip()) > 0

    @pytest.mark.integration
    @patch("ssl_checkup.connection.get_certificate")
    def test_subject_flag(self, mock_get_cert):
        """Test subject flag."""
        mock_cert = {"subject": [[("commonName", "example.com")]]}

        mock_get_cert.return_value = {"cert": mock_cert}

        result = subprocess.run(
            [sys.executable, "-m", "ssl_checkup.main", "example.com", "--subject"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "example.com" in result.stdout

    @pytest.mark.integration
    def test_san_flag(self):
        """Test SAN flag."""
        result = subprocess.run(
            [sys.executable, "-m", "ssl_checkup.main", "example.com", "--san"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        # Check that some SAN information is present (real certificate may change)
        assert "example.com" in result.stdout
        assert len(result.stdout.strip()) > 0

    @pytest.mark.integration
    def test_invalid_hostname(self):
        """Test behavior with invalid hostname."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "ssl_checkup.main",
                "invalid.hostname.that.does.not.exist",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 2
        assert "Could not resolve" in result.stderr

    @pytest.mark.integration
    @patch("ssl_checkup.connection.get_certificate")
    def test_no_color_flag(self, mock_get_cert):
        """Test no-color flag."""
        mock_cert = {
            "notAfter": "Dec 15 23:59:59 2024 GMT",
            "notBefore": "Sep 15 00:00:00 2024 GMT",
            "subject": [[("commonName", "example.com")]],
            "issuer": [[("organizationName", "Example CA")]],
            "subjectAltName": [("DNS", "example.com")],
        }

        mock_get_cert.return_value = {"cert": mock_cert}

        result = subprocess.run(
            [sys.executable, "-m", "ssl_checkup.main", "example.com", "--no-color"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "Certificate for:" in result.stdout

    @pytest.mark.integration
    @patch("ssl_checkup.connection.get_certificate")
    def test_debug_flag(self, mock_get_cert):
        """Test debug flag."""
        mock_cert_info = {
            "cert": {
                "notAfter": "Dec 15 23:59:59 2024 GMT",
                "notBefore": "Sep 15 00:00:00 2024 GMT",
                "subject": [[("commonName", "example.com")]],
                "issuer": [[("organizationName", "Example CA")]],
                "subjectAltName": [("DNS", "example.com")],
            },
            "pem": "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----",
            "resolved_ip": "93.184.216.34",
            "tls_version": "TLSv1.3",
            "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        }

        mock_get_cert.return_value = mock_cert_info

        result = subprocess.run(
            [sys.executable, "-m", "ssl_checkup.main", "example.com", "--debug"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "[DEBUG]" in result.stdout

    @pytest.mark.integration
    @patch("ssl_checkup.connection.get_certificate")
    def test_insecure_flag(self, mock_get_cert):
        """Test insecure flag."""
        mock_cert = {
            "notAfter": "Dec 15 23:59:59 2024 GMT",
            "notBefore": "Sep 15 00:00:00 2024 GMT",
            "subject": [[("commonName", "example.com")]],
            "issuer": [[("organizationName", "Example CA")]],
            "subjectAltName": [("DNS", "example.com")],
        }

        mock_get_cert.return_value = {"cert": mock_cert}

        result = subprocess.run(
            [sys.executable, "-m", "ssl_checkup.main", "example.com", "--insecure"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "Certificate for:" in result.stdout

    @pytest.mark.integration
    def test_custom_port(self):
        """Test custom port parsing by using a non-existent hostname."""
        result = subprocess.run(
            [sys.executable, "-m", "ssl_checkup.main", "nonexistent.invalid:8443"],
            capture_output=True,
            text=True,
            timeout=10,  # Add timeout to prevent hanging
        )

        # Should fail to connect but parse correctly
        assert result.returncode != 0
        # Error message should mention connection issue (resolution failure)
        assert (
            "resolve" in result.stderr.lower()
            or "not found" in result.stderr.lower()
            or "does not exist" in result.stderr.lower()
            or "failed" in result.stderr.lower()
        )


class TestPackageIntegration:
    """Integration tests for package functionality."""

    def test_package_import(self):
        """Test that the package can be imported correctly."""
        import ssl_checkup

        assert hasattr(ssl_checkup, "main")
        assert hasattr(ssl_checkup, "__version__")
        assert ssl_checkup.__version__ == "1.0.0"

    def test_module_execution(self):
        """Test that the module can be executed with -m flag."""
        result = subprocess.run(
            [sys.executable, "-m", "ssl_checkup"], capture_output=True, text=True
        )

        # Should show help when no arguments
        assert result.returncode == 1
        assert "usage:" in result.stderr or "usage:" in result.stdout

    def test_all_imports(self):
        """Test that all modules can be imported without errors."""
        from ssl_checkup import (
            cli,
            connection,
            display,
            exceptions,
            formatting,
            parser,
        )
        from ssl_checkup.main import main as main_function

        # Test that key functions exist
        assert callable(main_function)
        assert hasattr(cli, "create_parser")
        assert hasattr(connection, "get_certificate")
        assert hasattr(parser, "parse_san")
        assert hasattr(display, "pretty_print_cert")
        assert hasattr(formatting, "OutputFormatter")
        assert hasattr(exceptions, "handle_socket_error")

    def test_entry_point_execution(self):
        """Test that the entry point works correctly."""
        # This test would typically run the installed command
        # For now, we'll test the main function directly
        from ssl_checkup.main import main

        # Test that main function exists and is callable
        assert callable(main)

"""Integration tests for ssl-checkup package."""

import subprocess
import sys
from io import StringIO
from unittest.mock import patch

from ssl_checkup.main import main


class TestCliSubprocessSmoke:
    """Subprocess smoke tests for module execution."""

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
            [sys.executable, "-m", "ssl_checkup.main"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 1
        assert "usage:" in result.stderr or "usage:" in result.stdout


class TestCliInProcessIntegration:
    """In-process integration tests for CLI behavior with mocks."""

    @patch("ssl_checkup.main.get_certificate")
    @patch("sys.stdout", new_callable=StringIO)
    def test_basic_certificate_check(self, _mock_stdout, mock_get_cert):
        """Test basic certificate checking functionality."""
        mock_cert = {
            "notAfter": "Dec 15 23:59:59 2030 GMT",
            "notBefore": "Sep 15 00:00:00 2024 GMT",
            "subject": [[("commonName", "example.com")]],
            "issuer": [[("organizationName", "Example CA")]],
            "subjectAltName": [("DNS", "example.com")],
        }
        mock_get_cert.return_value = {"cert": mock_cert}

        with patch.object(sys, "argv", ["ssl-checkup", "example.com"]):
            main()

        mock_get_cert.assert_called_once_with("example.com", 443, insecure=False)

    @patch("ssl_checkup.main.get_certificate")
    @patch("sys.stdout", new_callable=StringIO)
    def test_print_cert_flag(self, mock_stdout, mock_get_cert):
        """Test print certificate flag."""
        mock_get_cert.return_value = (
            "-----BEGIN CERTIFICATE-----\nMOCK_CERT_DATA\n-----END CERTIFICATE-----"
        )

        with patch.object(sys, "argv", ["ssl-checkup", "example.com", "--print-cert"]):
            main()

        assert "BEGIN CERTIFICATE" in mock_stdout.getvalue()
        assert "END CERTIFICATE" in mock_stdout.getvalue()

    @patch("ssl_checkup.main.get_certificate")
    @patch("sys.stdout", new_callable=StringIO)
    def test_issuer_flag(self, mock_stdout, mock_get_cert):
        """Test issuer flag."""
        mock_get_cert.return_value = {
            "cert": {"issuer": [[("organizationName", "Example CA")]]}
        }

        with patch.object(sys, "argv", ["ssl-checkup", "example.com", "--issuer"]):
            main()

        assert "Example CA" in mock_stdout.getvalue()

    @patch("ssl_checkup.main.get_certificate")
    @patch("sys.stdout", new_callable=StringIO)
    def test_subject_flag(self, mock_stdout, mock_get_cert):
        """Test subject flag."""
        mock_get_cert.return_value = {
            "cert": {"subject": [[("commonName", "example.com")]]}
        }

        with patch.object(sys, "argv", ["ssl-checkup", "example.com", "--subject"]):
            main()

        assert "example.com" in mock_stdout.getvalue()

    @patch("ssl_checkup.main.get_certificate")
    @patch("sys.stdout", new_callable=StringIO)
    def test_san_flag(self, mock_stdout, mock_get_cert):
        """Test SAN flag."""
        mock_get_cert.return_value = {
            "cert": {
                "subjectAltName": [("DNS", "example.com"), ("DNS", "www.example.com")]
            }
        }

        with patch.object(sys, "argv", ["ssl-checkup", "example.com", "--san"]):
            main()

        output = mock_stdout.getvalue()
        assert "example.com" in output
        assert "www.example.com" in output

    @patch("ssl_checkup.main.get_certificate")
    @patch("sys.stdout", new_callable=StringIO)
    def test_no_color_flag(self, _mock_stdout, mock_get_cert):
        """Test no-color flag."""
        mock_get_cert.return_value = {
            "cert": {
                "notAfter": "Dec 15 23:59:59 2030 GMT",
                "notBefore": "Sep 15 00:00:00 2024 GMT",
                "subject": [[("commonName", "example.com")]],
                "issuer": [[("organizationName", "Example CA")]],
                "subjectAltName": [("DNS", "example.com")],
            }
        }

        with patch.object(sys, "argv", ["ssl-checkup", "example.com", "--no-color"]):
            main()

        mock_get_cert.assert_called_once_with("example.com", 443, insecure=False)

    @patch("ssl_checkup.main.get_certificate")
    @patch("sys.stdout", new_callable=StringIO)
    def test_debug_flag(self, mock_stdout, mock_get_cert):
        """Test debug flag."""
        mock_get_cert.return_value = {
            "cert": {
                "notAfter": "Dec 15 23:59:59 2030 GMT",
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

        with patch.object(sys, "argv", ["ssl-checkup", "example.com", "--debug"]):
            main()

        assert "[DEBUG]" in mock_stdout.getvalue()

    @patch("ssl_checkup.main.get_certificate")
    @patch("sys.stdout", new_callable=StringIO)
    def test_insecure_flag(self, _mock_stdout, mock_get_cert):
        """Test insecure flag."""
        mock_get_cert.return_value = {
            "cert": {
                "notAfter": "Dec 15 23:59:59 2030 GMT",
                "notBefore": "Sep 15 00:00:00 2024 GMT",
                "subject": [[("commonName", "example.com")]],
                "issuer": [[("organizationName", "Example CA")]],
                "subjectAltName": [("DNS", "example.com")],
            }
        }

        with patch.object(sys, "argv", ["ssl-checkup", "example.com", "--insecure"]):
            main()

        mock_get_cert.assert_called_once_with("example.com", 443, insecure=True)

    @patch("sys.stderr", new_callable=StringIO)
    def test_invalid_port_friendly_error(self, mock_stderr):
        """Test invalid port shows parser error, not traceback."""
        with patch.object(sys, "argv", ["ssl-checkup", "example.com:notaport"]):
            try:
                main()
            except SystemExit as exc:
                assert exc.code == 2

        assert "Invalid website argument" in mock_stderr.getvalue()


class TestPackageIntegration:
    """Integration tests for package functionality."""

    def test_package_import(self):
        """Test that the package can be imported correctly."""
        import ssl_checkup

        assert hasattr(ssl_checkup, "main")
        assert hasattr(ssl_checkup, "__version__")
        assert ssl_checkup.__version__ == "1.0.2"

    def test_module_execution(self):
        """Test that the module can be executed with -m flag."""
        result = subprocess.run(
            [sys.executable, "-m", "ssl_checkup"],
            capture_output=True,
            text=True,
        )

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

        assert callable(main_function)
        assert hasattr(cli, "create_parser")
        assert hasattr(connection, "get_certificate")
        assert hasattr(parser, "parse_san")
        assert hasattr(display, "pretty_print_cert")
        assert hasattr(formatting, "OutputFormatter")
        assert hasattr(exceptions, "handle_socket_error")

    def test_entry_point_execution(self):
        """Test that the entry point works correctly."""
        from ssl_checkup.main import main as main_function

        assert callable(main_function)

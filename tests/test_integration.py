"""Integration tests for ssl-checkup package."""

import json
import socket
import subprocess
import sys
from datetime import datetime, timedelta
from io import StringIO
from unittest.mock import patch

import pytest

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

        mock_get_cert.assert_called_once_with(
            "example.com",
            443,
            insecure=False,
            timeout=10.0,
            ip_version="auto",
        )

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

        mock_get_cert.assert_called_once_with(
            "example.com",
            443,
            insecure=False,
            timeout=10.0,
            ip_version="auto",
        )

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

        mock_get_cert.assert_called_once_with(
            "example.com",
            443,
            insecure=True,
            timeout=10.0,
            ip_version="auto",
        )

    @patch("sys.stderr", new_callable=StringIO)
    def test_invalid_port_friendly_error(self, mock_stderr):
        """Test invalid port shows parser error, not traceback."""
        with patch.object(sys, "argv", ["ssl-checkup", "example.com:notaport"]):
            try:
                main()
            except SystemExit as exc:
                assert exc.code == 2

        assert "Invalid website argument" in mock_stderr.getvalue()

    @patch("ssl_checkup.main.get_certificate")
    @patch("sys.stdout", new_callable=StringIO)
    def test_json_output(self, mock_stdout, mock_get_cert):
        """Test JSON output mode."""
        future_date = datetime.utcnow() + timedelta(days=60)
        past_date = datetime.utcnow() - timedelta(days=10)
        mock_get_cert.return_value = {
            "cert": {
                "notAfter": future_date.strftime("%b %d %H:%M:%S %Y GMT"),
                "notBefore": past_date.strftime("%b %d %H:%M:%S %Y GMT"),
                "subject": [[("commonName", "example.com")]],
                "issuer": [[("organizationName", "Example CA")]],
                "subjectAltName": [("DNS", "example.com")],
            },
            "pem": "",
            "resolved_ip": "93.184.216.34",
            "tls_version": "TLSv1.3",
            "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        }

        with patch.object(sys, "argv", ["ssl-checkup", "example.com", "--json"]):
            main()

        payload = json.loads(mock_stdout.getvalue())
        assert payload["hostname"] == "example.com"
        assert payload["hostname_match"] is True
        assert payload["status"] == "valid"
        assert payload["days_left"] >= 0

    @patch("ssl_checkup.main.get_certificate")
    def test_warn_exit_code(self, mock_get_cert):
        """Test warning threshold exit code."""
        near_date = datetime.utcnow() + timedelta(days=5)
        past_date = datetime.utcnow() - timedelta(days=10)
        mock_get_cert.return_value = {
            "cert": {
                "notAfter": near_date.strftime("%b %d %H:%M:%S %Y GMT"),
                "notBefore": past_date.strftime("%b %d %H:%M:%S %Y GMT"),
                "subject": [[("commonName", "example.com")]],
                "issuer": [[("organizationName", "Example CA")]],
                "subjectAltName": [("DNS", "example.com")],
            },
            "pem": "",
        }

        with patch.object(
            sys,
            "argv",
            ["ssl-checkup", "example.com", "--warn-days", "10", "--critical-days", "3"],
        ):
            with pytest.raises(SystemExit) as exc:
                main()
        assert exc.value.code == 1

    @patch("ssl_checkup.main.get_certificate")
    def test_critical_exit_code(self, mock_get_cert):
        """Test critical threshold exit code."""
        near_date = datetime.utcnow() + timedelta(days=1)
        past_date = datetime.utcnow() - timedelta(days=10)
        mock_get_cert.return_value = {
            "cert": {
                "notAfter": near_date.strftime("%b %d %H:%M:%S %Y GMT"),
                "notBefore": past_date.strftime("%b %d %H:%M:%S %Y GMT"),
                "subject": [[("commonName", "example.com")]],
                "issuer": [[("organizationName", "Example CA")]],
                "subjectAltName": [("DNS", "example.com")],
            },
            "pem": "",
        }

        with patch.object(
            sys,
            "argv",
            ["ssl-checkup", "example.com", "--warn-days", "10", "--critical-days", "2"],
        ):
            with pytest.raises(SystemExit) as exc:
                main()
        assert exc.value.code == 2

    @patch("ssl_checkup.main.get_certificate")
    @patch("sys.stdout", new_callable=StringIO)
    def test_batch_input_json(self, mock_stdout, mock_get_cert, tmp_path):
        """Test batch mode with input file and JSON output."""
        target_file = tmp_path / "targets.txt"
        target_file.write_text("example.com\nexample.org:8443\n", encoding="utf-8")

        future_date = datetime.utcnow() + timedelta(days=90)
        past_date = datetime.utcnow() - timedelta(days=30)
        mock_get_cert.return_value = {
            "cert": {
                "notAfter": future_date.strftime("%b %d %H:%M:%S %Y GMT"),
                "notBefore": past_date.strftime("%b %d %H:%M:%S %Y GMT"),
                "subject": [[("commonName", "example.com")]],
                "issuer": [[("organizationName", "Example CA")]],
                "subjectAltName": [("DNS", "example.com")],
            },
            "pem": "",
            "resolved_ip": "93.184.216.34",
            "tls_version": "TLSv1.3",
            "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        }

        with patch.object(
            sys,
            "argv",
            [
                "ssl-checkup",
                "--input",
                str(target_file),
                "--json",
                "--workers",
                "2",
                "--timeout",
                "3",
                "--ip-version",
                "4",
            ],
        ):
            main()

        payload = json.loads(mock_stdout.getvalue())
        assert isinstance(payload, list)
        assert len(payload) == 2
        assert payload[0]["hostname_match"] is True
        assert payload[1]["hostname_match"] is False
        assert payload[0]["status"] == "valid"

    @patch("ssl_checkup.main.get_certificate")
    @patch("sys.stdout", new_callable=StringIO)
    def test_batch_input_json_with_summary(self, mock_stdout, mock_get_cert, tmp_path):
        """Test batch mode JSON summary output."""
        target_file = tmp_path / "targets.txt"
        target_file.write_text("example.com\nexample.org:8443\n", encoding="utf-8")

        future_date = datetime.utcnow() + timedelta(days=90)
        past_date = datetime.utcnow() - timedelta(days=30)
        mock_get_cert.return_value = {
            "cert": {
                "notAfter": future_date.strftime("%b %d %H:%M:%S %Y GMT"),
                "notBefore": past_date.strftime("%b %d %H:%M:%S %Y GMT"),
                "subject": [[("commonName", "example.com")]],
                "issuer": [[("organizationName", "Example CA")]],
                "subjectAltName": [("DNS", "example.com")],
            },
            "pem": "",
            "resolved_ip": "93.184.216.34",
            "tls_version": "TLSv1.3",
            "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        }

        with patch.object(
            sys,
            "argv",
            [
                "ssl-checkup",
                "--input",
                str(target_file),
                "--json",
                "--summary",
            ],
        ):
            main()

        payload = json.loads(mock_stdout.getvalue())
        assert "results" in payload
        assert "summary" in payload
        assert payload["summary"]["total"] == 2
        assert payload["summary"]["errors"] == 0

    @patch("ssl_checkup.main.get_certificate")
    def test_batch_fail_fast_stops_on_first_error(self, mock_get_cert, tmp_path):
        """Test --fail-fast stops processing after first failure."""
        target_file = tmp_path / "targets.txt"
        target_file.write_text("example.com\nexample.org:8443\n", encoding="utf-8")

        mock_get_cert.side_effect = socket.timeout("timed out")

        with patch.object(
            sys,
            "argv",
            ["ssl-checkup", "--input", str(target_file), "--fail-fast"],
        ):
            with pytest.raises(SystemExit) as exc:
                main()

        assert exc.value.code == 10
        assert mock_get_cert.call_count == 1

    @patch("ssl_checkup.main.get_certificate")
    @patch("sys.stdout", new_callable=StringIO)
    def test_json_output_with_chain(self, mock_stdout, mock_get_cert):
        """Test JSON output with certificate chain summary."""
        future_date = datetime.utcnow() + timedelta(days=60)
        past_date = datetime.utcnow() - timedelta(days=10)
        mock_get_cert.return_value = {
            "cert": {
                "notAfter": future_date.strftime("%b %d %H:%M:%S %Y GMT"),
                "notBefore": past_date.strftime("%b %d %H:%M:%S %Y GMT"),
                "subject": [[("commonName", "example.com")]],
                "issuer": [[("organizationName", "Example CA")]],
                "subjectAltName": [("DNS", "example.com")],
            },
            "pem": "",
            "resolved_ip": "93.184.216.34",
            "tls_version": "TLSv1.3",
            "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
            "chain_pem": [
                "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----",
                "-----BEGIN CERTIFICATE-----\nissuer\n-----END CERTIFICATE-----",
            ],
            "chain_source": "verified",
        }

        with patch.object(
            sys,
            "argv",
            ["ssl-checkup", "example.com", "--json", "--show-chain"],
        ):
            main()

        payload = json.loads(mock_stdout.getvalue())
        assert payload["chain_source"] == "verified"
        assert len(payload["chain"]) == 2

    @patch("ssl_checkup.main.get_certificate")
    @patch("sys.stdout", new_callable=StringIO)
    def test_retries_succeed_after_transient_failure(self, _mock_stdout, mock_get_cert):
        """Test retry behavior for transient connection failures."""
        future_date = datetime.utcnow() + timedelta(days=60)
        past_date = datetime.utcnow() - timedelta(days=10)
        mock_get_cert.side_effect = [
            socket.timeout("timed out"),
            {
                "cert": {
                    "notAfter": future_date.strftime("%b %d %H:%M:%S %Y GMT"),
                    "notBefore": past_date.strftime("%b %d %H:%M:%S %Y GMT"),
                    "subject": [[("commonName", "example.com")]],
                    "issuer": [[("organizationName", "Example CA")]],
                    "subjectAltName": [("DNS", "example.com")],
                },
                "pem": "",
                "resolved_ip": "93.184.216.34",
                "tls_version": "TLSv1.3",
                "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
            },
        ]

        with patch.object(
            sys,
            "argv",
            [
                "ssl-checkup",
                "example.com",
                "--json",
                "--retries",
                "1",
                "--retry-delay",
                "0",
            ],
        ):
            main()

        assert mock_get_cert.call_count == 2

    @patch("ssl_checkup.main.get_certificate")
    def test_retries_exhausted(self, mock_get_cert):
        """Test behavior when retries are exhausted."""
        mock_get_cert.side_effect = socket.timeout("timed out")

        with patch.object(
            sys,
            "argv",
            ["ssl-checkup", "example.com", "--retries", "1", "--retry-delay", "0"],
        ):
            with pytest.raises(SystemExit) as exc:
                main()

        assert exc.value.code == 12
        assert mock_get_cert.call_count == 2

    @patch("ssl_checkup.main.get_certificate")
    def test_output_file_json(self, mock_get_cert, tmp_path):
        """Test writing JSON output directly to a file."""
        future_date = datetime.utcnow() + timedelta(days=60)
        past_date = datetime.utcnow() - timedelta(days=10)
        mock_get_cert.return_value = {
            "cert": {
                "notAfter": future_date.strftime("%b %d %H:%M:%S %Y GMT"),
                "notBefore": past_date.strftime("%b %d %H:%M:%S %Y GMT"),
                "subject": [[("commonName", "example.com")]],
                "issuer": [[("organizationName", "Example CA")]],
                "subjectAltName": [("DNS", "example.com")],
            },
            "pem": "",
            "resolved_ip": "93.184.216.34",
            "tls_version": "TLSv1.3",
            "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        }

        output_file = tmp_path / "report.json"
        with patch.object(
            sys,
            "argv",
            ["ssl-checkup", "example.com", "--json", "--output", str(output_file)],
        ):
            main()

        payload = json.loads(output_file.read_text(encoding="utf-8"))
        assert payload["hostname"] == "example.com"
        assert payload["status"] == "valid"


class TestPackageIntegration:
    """Integration tests for package functionality."""

    def test_package_import(self):
        """Test that the package can be imported correctly."""
        import ssl_checkup

        assert hasattr(ssl_checkup, "main")
        assert hasattr(ssl_checkup, "__version__")
        assert ssl_checkup.__version__ == "1.1.1"

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

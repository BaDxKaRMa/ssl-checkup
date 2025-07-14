"""Tests for main module."""

from io import StringIO
from unittest.mock import Mock, patch

import pytest

from ssl_checkup.main import main, print_single_field


class TestPrintSingleField:
    """Test single field printing functionality."""

    @patch("builtins.print")
    def test_print_single_field_issuer(self, mock_print, sample_cert):
        """Test printing issuer field."""
        print_single_field(sample_cert, "issuer")

        mock_print.assert_called_once_with("Let's Encrypt")

    @patch("builtins.print")
    def test_print_single_field_subject(self, mock_print, sample_cert):
        """Test printing subject field."""
        print_single_field(sample_cert, "subject")

        mock_print.assert_called_once_with("example.com")

    @patch("builtins.print")
    def test_print_single_field_san(self, mock_print, sample_cert):
        """Test printing SAN field."""
        print_single_field(sample_cert, "san")

        # Should print each SAN on a separate line
        assert mock_print.call_count == 3
        mock_print.assert_any_call("example.com")
        mock_print.assert_any_call("www.example.com")
        mock_print.assert_any_call("api.example.com")

    @patch("builtins.print")
    def test_print_single_field_issuer_na(self, mock_print):
        """Test printing issuer field when not available."""
        cert = {"issuer": []}

        print_single_field(cert, "issuer")

        mock_print.assert_called_once_with("N/A")

    @patch("builtins.print")
    def test_print_single_field_subject_na(self, mock_print):
        """Test printing subject field when not available."""
        cert = {"subject": []}

        print_single_field(cert, "subject")

        mock_print.assert_called_once_with("N/A")

    @patch("builtins.print")
    def test_print_single_field_san_empty(self, mock_print):
        """Test printing SAN field when empty."""
        cert = {"subjectAltName": []}

        print_single_field(cert, "san")

        # Should not print anything for empty SAN
        mock_print.assert_not_called()

    def test_print_single_field_invalid_field(self, sample_cert):
        """Test printing invalid field type."""
        with pytest.raises(ValueError, match="Unknown field type: invalid"):
            print_single_field(sample_cert, "invalid")


class TestMain:
    """Test main application functionality."""

    @patch("ssl_checkup.main.create_parser")
    @patch("ssl_checkup.main.handle_version_check")
    @patch("ssl_checkup.main.validate_args")
    @patch("ssl_checkup.main.parse_website_arg")
    @patch("ssl_checkup.main.get_certificate")
    @patch("ssl_checkup.main.pretty_print_cert")
    def test_main_basic_flow(
        self,
        mock_pretty_print,
        mock_get_cert,
        mock_parse_website,
        mock_validate,
        mock_version_check,
        mock_create_parser,
        sample_cert,
    ):
        """Test basic main application flow."""
        # Setup mocks
        mock_parser = Mock()
        mock_args = Mock()
        mock_args.debug = False
        mock_args.no_color = False
        mock_args.print_cert = False
        mock_args.insecure = False
        mock_args.issuer = False
        mock_args.subject = False
        mock_args.san = False
        mock_args.website = "example.com"

        mock_create_parser.return_value = mock_parser
        mock_parser.parse_args.return_value = mock_args
        mock_parse_website.return_value = ("example.com", 443)
        mock_get_cert.return_value = {"cert": sample_cert}

        main()

        # Verify flow
        mock_create_parser.assert_called_once()
        mock_parser.parse_args.assert_called_once()
        mock_version_check.assert_called_once_with(mock_args)
        mock_validate.assert_called_once_with(mock_args, mock_parser)
        mock_parse_website.assert_called_once_with("example.com")
        mock_get_cert.assert_called_once_with("example.com", 443, insecure=False)
        mock_pretty_print.assert_called_once()

    @patch("ssl_checkup.main.create_parser")
    @patch("ssl_checkup.main.handle_version_check")
    @patch("ssl_checkup.main.validate_args")
    @patch("ssl_checkup.main.parse_website_arg")
    @patch("ssl_checkup.main.get_certificate")
    @patch("builtins.print")
    def test_main_print_cert_mode(
        self,
        mock_print,
        mock_get_cert,
        mock_parse_website,
        mock_validate,
        mock_version_check,
        mock_create_parser,
    ):
        """Test main application with print certificate mode."""
        # Setup mocks
        mock_parser = Mock()
        mock_args = Mock()
        mock_args.debug = False
        mock_args.no_color = False
        mock_args.print_cert = True
        mock_args.insecure = False
        mock_args.website = "example.com"

        mock_create_parser.return_value = mock_parser
        mock_parser.parse_args.return_value = mock_args
        mock_parse_website.return_value = ("example.com", 443)
        mock_get_cert.return_value = (
            "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----"
        )

        main()

        # Verify PEM certificate is printed
        mock_get_cert.assert_called_once_with(
            "example.com", 443, pem=True, insecure=False
        )
        mock_print.assert_called_once_with(
            "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----"
        )

    @patch("ssl_checkup.main.create_parser")
    @patch("ssl_checkup.main.handle_version_check")
    @patch("ssl_checkup.main.validate_args")
    @patch("ssl_checkup.main.parse_website_arg")
    @patch("ssl_checkup.main.get_certificate")
    @patch("ssl_checkup.main.print_single_field")
    def test_main_issuer_mode(
        self,
        mock_print_field,
        mock_get_cert,
        mock_parse_website,
        mock_validate,
        mock_version_check,
        mock_create_parser,
        sample_cert,
    ):
        """Test main application with issuer mode."""
        # Setup mocks
        mock_parser = Mock()
        mock_args = Mock()
        mock_args.debug = False
        mock_args.no_color = False
        mock_args.print_cert = False
        mock_args.insecure = False
        mock_args.issuer = True
        mock_args.subject = False
        mock_args.san = False
        mock_args.website = "example.com"

        mock_create_parser.return_value = mock_parser
        mock_parser.parse_args.return_value = mock_args
        mock_parse_website.return_value = ("example.com", 443)
        mock_get_cert.return_value = {"cert": sample_cert}

        main()

        # Verify issuer is printed
        mock_print_field.assert_called_once_with(sample_cert, "issuer")

    @patch("ssl_checkup.main.create_parser")
    @patch("ssl_checkup.main.handle_version_check")
    @patch("ssl_checkup.main.validate_args")
    @patch("ssl_checkup.main.parse_website_arg")
    @patch("ssl_checkup.main.get_certificate")
    @patch("ssl_checkup.main.print_single_field")
    def test_main_subject_mode(
        self,
        mock_print_field,
        mock_get_cert,
        mock_parse_website,
        mock_validate,
        mock_version_check,
        mock_create_parser,
        sample_cert,
    ):
        """Test main application with subject mode."""
        # Setup mocks
        mock_parser = Mock()
        mock_args = Mock()
        mock_args.debug = False
        mock_args.no_color = False
        mock_args.print_cert = False
        mock_args.insecure = False
        mock_args.issuer = False
        mock_args.subject = True
        mock_args.san = False
        mock_args.website = "example.com"

        mock_create_parser.return_value = mock_parser
        mock_parser.parse_args.return_value = mock_args
        mock_parse_website.return_value = ("example.com", 443)
        mock_get_cert.return_value = {"cert": sample_cert}

        main()

        # Verify subject is printed
        mock_print_field.assert_called_once_with(sample_cert, "subject")

    @patch("ssl_checkup.main.create_parser")
    @patch("ssl_checkup.main.handle_version_check")
    @patch("ssl_checkup.main.validate_args")
    @patch("ssl_checkup.main.parse_website_arg")
    @patch("ssl_checkup.main.get_certificate")
    @patch("ssl_checkup.main.print_single_field")
    def test_main_san_mode(
        self,
        mock_print_field,
        mock_get_cert,
        mock_parse_website,
        mock_validate,
        mock_version_check,
        mock_create_parser,
        sample_cert,
    ):
        """Test main application with SAN mode."""
        # Setup mocks
        mock_parser = Mock()
        mock_args = Mock()
        mock_args.debug = False
        mock_args.no_color = False
        mock_args.print_cert = False
        mock_args.insecure = False
        mock_args.issuer = False
        mock_args.subject = False
        mock_args.san = True
        mock_args.website = "example.com"

        mock_create_parser.return_value = mock_parser
        mock_parser.parse_args.return_value = mock_args
        mock_parse_website.return_value = ("example.com", 443)
        mock_get_cert.return_value = {"cert": sample_cert}

        main()

        # Verify SAN is printed
        mock_print_field.assert_called_once_with(sample_cert, "san")

    @patch("ssl_checkup.main.create_parser")
    @patch("ssl_checkup.main.handle_version_check")
    @patch("ssl_checkup.main.validate_args")
    @patch("ssl_checkup.main.parse_website_arg")
    @patch("ssl_checkup.main.get_certificate")
    @patch("ssl_checkup.main.DebugFormatter")
    @patch("ssl_checkup.main.pretty_print_cert")
    @patch("ssl_checkup.main.time.time")
    def test_main_debug_mode(
        self,
        mock_time,
        mock_pretty_print,
        mock_debug_formatter,
        mock_get_cert,
        mock_parse_website,
        mock_validate,
        mock_version_check,
        mock_create_parser,
        mock_cert_info,
    ):
        """Test main application with debug mode."""
        # Setup mocks
        mock_parser = Mock()
        mock_args = Mock()
        mock_args.debug = True
        mock_args.no_color = False
        mock_args.print_cert = False
        mock_args.insecure = False
        mock_args.issuer = False
        mock_args.subject = False
        mock_args.san = False
        mock_args.website = "example.com"

        mock_create_parser.return_value = mock_parser
        mock_parser.parse_args.return_value = mock_args
        mock_parse_website.return_value = ("example.com", 443)
        mock_get_cert.return_value = mock_cert_info
        mock_time.return_value = 1.0

        mock_formatter = Mock()
        mock_debug_formatter.return_value = mock_formatter

        main()

        # Verify debug formatter is created and used
        mock_debug_formatter.assert_called_once_with(True)
        mock_formatter.print_connection_details.assert_called_once()
        mock_formatter.print_cert_details.assert_called_once()
        mock_formatter.print_query_analysis.assert_called_once()

    @patch("ssl_checkup.main.create_parser")
    @patch("ssl_checkup.main.handle_version_check")
    @patch("ssl_checkup.main.validate_args")
    @patch("ssl_checkup.main.parse_website_arg")
    @patch("ssl_checkup.main.get_certificate")
    @patch("sys.exit")
    @patch("sys.stderr", new_callable=StringIO)
    def test_main_invalid_cert_dict(
        self,
        mock_stderr,
        mock_exit,
        mock_get_cert,
        mock_parse_website,
        mock_validate,
        mock_version_check,
        mock_create_parser,
    ):
        """Test main application with invalid certificate dictionary."""
        # Setup mocks
        mock_parser = Mock()
        mock_args = Mock()
        mock_args.debug = False
        mock_args.no_color = False
        mock_args.print_cert = False
        mock_args.insecure = False
        mock_args.issuer = False
        mock_args.subject = False
        mock_args.san = False
        mock_args.website = "example.com"

        mock_create_parser.return_value = mock_parser
        mock_parser.parse_args.return_value = mock_args
        mock_parse_website.return_value = ("example.com", 443)
        mock_get_cert.return_value = "not a dict"

        main()

        # Verify error handling
        error_output = mock_stderr.getvalue()
        assert "Error: Could not parse certificate details." in error_output
        mock_exit.assert_called_with(1)

    @patch("ssl_checkup.main.create_parser")
    @patch("ssl_checkup.main.handle_version_check")
    @patch("ssl_checkup.main.validate_args")
    @patch("ssl_checkup.main.parse_website_arg")
    @patch("ssl_checkup.main.get_certificate")
    @patch("ssl_checkup.main.handle_keyboard_interrupt")
    def test_main_keyboard_interrupt(
        self,
        mock_handle_interrupt,
        mock_get_cert,
        mock_parse_website,
        mock_validate,
        mock_version_check,
        mock_create_parser,
    ):
        """Test main application with keyboard interrupt."""
        # Setup mocks for normal flow
        mock_parser = Mock()
        mock_args = Mock()
        mock_args.debug = False
        mock_args.no_color = False
        mock_args.print_cert = False
        mock_args.insecure = False
        mock_args.issuer = False
        mock_args.subject = False
        mock_args.san = False
        mock_args.website = "example.com"

        mock_create_parser.return_value = mock_parser
        mock_parser.parse_args.return_value = mock_args
        mock_parse_website.return_value = ("example.com", 443)

        # Trigger KeyboardInterrupt during certificate retrieval (inside try-catch)
        mock_get_cert.side_effect = KeyboardInterrupt()

        # The KeyboardInterrupt should be caught by main() and handled
        main()

        mock_handle_interrupt.assert_called_once()

    @patch("ssl_checkup.main.create_parser")
    @patch("ssl_checkup.main.handle_version_check")
    @patch("ssl_checkup.main.validate_args")
    @patch("ssl_checkup.main.parse_website_arg")
    @patch("ssl_checkup.main.get_certificate")
    @patch("ssl_checkup.main.handle_socket_error")
    def test_main_socket_error(
        self,
        mock_handle_error,
        mock_get_cert,
        mock_parse_website,
        mock_validate,
        mock_version_check,
        mock_create_parser,
    ):
        """Test main application with socket error."""
        # Setup mocks
        mock_parser = Mock()
        mock_args = Mock()
        mock_args.debug = False
        mock_args.website = "example.com"

        mock_create_parser.return_value = mock_parser
        mock_parser.parse_args.return_value = mock_args
        mock_parse_website.return_value = ("example.com", 443)

        import socket

        error = socket.gaierror("Name or service not known")
        mock_get_cert.side_effect = error

        main()

        mock_handle_error.assert_called_once_with(error, "example.com", 443, False)

    @patch("ssl_checkup.main.create_parser")
    @patch("ssl_checkup.main.handle_version_check")
    @patch("ssl_checkup.main.validate_args")
    @patch("ssl_checkup.main.parse_website_arg")
    @patch("ssl_checkup.main.get_certificate")
    @patch("ssl_checkup.main.handle_ssl_error")
    def test_main_ssl_error(
        self,
        mock_handle_error,
        mock_get_cert,
        mock_parse_website,
        mock_validate,
        mock_version_check,
        mock_create_parser,
    ):
        """Test main application with SSL error."""
        # Setup mocks
        mock_parser = Mock()
        mock_args = Mock()
        mock_args.debug = False
        mock_args.website = "example.com"

        mock_create_parser.return_value = mock_parser
        mock_parser.parse_args.return_value = mock_args
        mock_parse_website.return_value = ("example.com", 443)

        import ssl

        error = ssl.SSLError("SSL handshake failed")
        mock_get_cert.side_effect = error

        main()

        mock_handle_error.assert_called_once_with(error, "example.com", 443, False)

    @patch("ssl_checkup.main.create_parser")
    @patch("ssl_checkup.main.handle_version_check")
    @patch("ssl_checkup.main.validate_args")
    @patch("ssl_checkup.main.parse_website_arg")
    @patch("ssl_checkup.main.get_certificate")
    @patch("ssl_checkup.main.handle_general_error")
    def test_main_general_error(
        self,
        mock_handle_error,
        mock_get_cert,
        mock_parse_website,
        mock_validate,
        mock_version_check,
        mock_create_parser,
    ):
        """Test main application with general error."""
        # Setup mocks
        mock_parser = Mock()
        mock_args = Mock()
        mock_args.debug = False
        mock_args.website = "example.com"

        mock_create_parser.return_value = mock_parser
        mock_parser.parse_args.return_value = mock_args
        mock_parse_website.return_value = ("example.com", 443)

        error = Exception("Something went wrong")
        mock_get_cert.side_effect = error

        main()

        mock_handle_error.assert_called_once_with(error, False)

    @patch("ssl_checkup.main.create_parser")
    @patch("ssl_checkup.main.handle_version_check")
    @patch("ssl_checkup.main.validate_args")
    @patch("ssl_checkup.main.parse_website_arg")
    @patch("ssl_checkup.main.get_certificate")
    @patch("ssl_checkup.main.pretty_print_cert")
    def test_main_insecure_mode(
        self,
        mock_pretty_print,
        mock_get_cert,
        mock_parse_website,
        mock_validate,
        mock_version_check,
        mock_create_parser,
        sample_cert,
    ):
        """Test main application with insecure mode."""
        # Setup mocks
        mock_parser = Mock()
        mock_args = Mock()
        mock_args.debug = False
        mock_args.no_color = False
        mock_args.print_cert = False
        mock_args.insecure = True
        mock_args.issuer = False
        mock_args.subject = False
        mock_args.san = False
        mock_args.website = "example.com"

        mock_create_parser.return_value = mock_parser
        mock_parser.parse_args.return_value = mock_args
        mock_parse_website.return_value = ("example.com", 443)
        mock_get_cert.return_value = {"cert": sample_cert}

        main()

        # Verify insecure flag is passed to get_certificate
        mock_get_cert.assert_called_once_with("example.com", 443, insecure=True)

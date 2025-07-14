"""Tests for cli module."""

from unittest.mock import Mock, patch

import pytest

from ssl_checkup.cli import (
    create_parser,
    handle_version_check,
    parse_website_arg,
    validate_args,
)


class TestCreateParser:
    """Test argument parser creation."""

    def test_parser_creation(self):
        """Test that parser is created with expected arguments."""
        parser = create_parser()

        # Check that parser exists
        assert parser is not None

        # Parse help to check available arguments
        with pytest.raises(SystemExit):
            parser.parse_args(["--help"])

    def test_website_argument(self):
        """Test website argument parsing."""
        parser = create_parser()

        args = parser.parse_args(["example.com"])
        assert args.website == "example.com"

    def test_insecure_flag(self):
        """Test insecure flag."""
        parser = create_parser()

        args = parser.parse_args(["example.com", "--insecure"])
        assert args.insecure is True

        args = parser.parse_args(["example.com", "-k"])
        assert args.insecure is True

        args = parser.parse_args(["example.com"])
        assert args.insecure is False

    def test_version_flag(self):
        """Test version flag."""
        parser = create_parser()

        args = parser.parse_args(["--version"])
        assert args.version is True

    def test_no_color_flag(self):
        """Test no-color flag."""
        parser = create_parser()

        args = parser.parse_args(["example.com", "--no-color"])
        assert args.no_color is True

    def test_print_cert_flag(self):
        """Test print-cert flag."""
        parser = create_parser()

        args = parser.parse_args(["example.com", "--print-cert"])
        assert args.print_cert is True

        args = parser.parse_args(["example.com", "-p"])
        assert args.print_cert is True

    def test_debug_flag(self):
        """Test debug flag."""
        parser = create_parser()

        args = parser.parse_args(["example.com", "--debug"])
        assert args.debug is True

    def test_single_field_flags(self):
        """Test single field output flags."""
        parser = create_parser()

        args = parser.parse_args(["example.com", "--issuer"])
        assert args.issuer is True

        args = parser.parse_args(["example.com", "-i"])
        assert args.issuer is True

        args = parser.parse_args(["example.com", "--subject"])
        assert args.subject is True

        args = parser.parse_args(["example.com", "-s"])
        assert args.subject is True

        args = parser.parse_args(["example.com", "--san"])
        assert args.san is True

        args = parser.parse_args(["example.com", "-a"])
        assert args.san is True


class TestParseWebsiteArg:
    """Test website argument parsing."""

    def test_hostname_only(self):
        """Test parsing hostname without port."""
        hostname, port = parse_website_arg("example.com")
        assert hostname == "example.com"
        assert port == 443

    def test_hostname_with_port(self):
        """Test parsing hostname with port."""
        hostname, port = parse_website_arg("example.com:8443")
        assert hostname == "example.com"
        assert port == 8443

    def test_hostname_with_standard_port(self):
        """Test parsing hostname with standard HTTPS port."""
        hostname, port = parse_website_arg("example.com:443")
        assert hostname == "example.com"
        assert port == 443

    def test_ip_address(self):
        """Test parsing IP address."""
        hostname, port = parse_website_arg("192.168.1.1")
        assert hostname == "192.168.1.1"
        assert port == 443

    def test_ip_address_with_port(self):
        """Test parsing IP address with port."""
        hostname, port = parse_website_arg("192.168.1.1:8080")
        assert hostname == "192.168.1.1"
        assert port == 8080

    def test_invalid_port(self):
        """Test parsing with invalid port."""
        with pytest.raises(ValueError):
            parse_website_arg("example.com:not_a_number")


class TestHandleVersionCheck:
    """Test version check handling."""

    @patch("ssl_checkup.cli.sys.exit")
    @patch("builtins.print")
    def test_version_check_exits(self, mock_print, mock_exit):
        """Test that version check prints version and exits."""
        args = Mock()
        args.version = True

        handle_version_check(args)

        mock_print.assert_called_once()
        mock_exit.assert_called_once_with(0)

    def test_version_check_no_exit(self):
        """Test that version check returns False when not requested."""
        args = Mock()
        args.version = False

        result = handle_version_check(args)
        assert result is False


class TestValidateArgs:
    """Test argument validation."""

    @patch("ssl_checkup.cli.sys.exit")
    def test_validate_args_no_website(self, mock_exit):
        """Test validation fails when no website provided."""
        args = Mock()
        args.website = None

        parser = Mock()

        validate_args(args, parser)

        parser.print_help.assert_called_once()
        mock_exit.assert_called_once_with(1)

    def test_validate_args_with_website(self):
        """Test validation passes when website provided."""
        args = Mock()
        args.website = "example.com"

        parser = Mock()

        # Should not raise or exit
        validate_args(args, parser)

        parser.print_help.assert_not_called()


class TestIntegration:
    """Test CLI integration scenarios."""

    def test_full_argument_parsing(self):
        """Test complete argument parsing scenario."""
        parser = create_parser()

        args = parser.parse_args(
            ["example.com:8443", "--insecure", "--debug", "--no-color"]
        )

        assert args.website == "example.com:8443"
        assert args.insecure is True
        assert args.debug is True
        assert args.no_color is True
        assert args.version is False
        assert args.print_cert is False
        assert args.issuer is False
        assert args.subject is False
        assert args.san is False

    def test_minimal_arguments(self):
        """Test minimal required arguments."""
        parser = create_parser()

        args = parser.parse_args(["example.com"])

        assert args.website == "example.com"
        assert args.insecure is False
        assert args.debug is False
        assert args.no_color is False
        assert args.version is False

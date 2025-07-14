"""Tests for exceptions module."""

import socket
import ssl
from io import StringIO
from unittest.mock import patch

from ssl_checkup.exceptions import (
    handle_general_error,
    handle_keyboard_interrupt,
    handle_socket_error,
    handle_ssl_error,
)


class TestHandleKeyboardInterrupt:
    """Test keyboard interrupt handling."""

    @patch("ssl_checkup.exceptions.sys.exit")
    @patch("sys.stderr", new_callable=StringIO)
    def test_handle_keyboard_interrupt(self, mock_stderr, mock_exit):
        """Test keyboard interrupt handling."""
        handle_keyboard_interrupt()

        error_output = mock_stderr.getvalue()
        assert "Operation cancelled by user." in error_output
        mock_exit.assert_called_once_with(130)


class TestHandleSocketError:
    """Test socket error handling."""

    @patch("ssl_checkup.exceptions.sys.exit")
    @patch("sys.stderr", new_callable=StringIO)
    def test_handle_socket_error_basic(self, mock_stderr, mock_exit):
        """Test basic socket error handling."""
        error = socket.gaierror("Name or service not known")

        handle_socket_error(error, "example.com", 443, False)

        error_output = mock_stderr.getvalue()
        assert "Could not resolve or connect to 'example.com:443'" in error_output
        assert "Please check the hostname and your network connection" in error_output
        mock_exit.assert_called_once_with(2)

    @patch("ssl_checkup.exceptions.sys.exit")
    @patch("ssl_checkup.exceptions.traceback.print_exc")
    @patch("sys.stderr", new_callable=StringIO)
    def test_handle_socket_error_debug(self, mock_stderr, mock_traceback, mock_exit):
        """Test socket error handling with debug enabled."""
        error = socket.gaierror("Name or service not known")

        handle_socket_error(error, "example.com", 443, True)

        error_output = mock_stderr.getvalue()
        assert "Could not resolve or connect to 'example.com:443'" in error_output
        assert "[DEBUG] socket.gaierror:" in error_output
        assert "Name or service not known" in error_output
        mock_traceback.assert_called_once()
        mock_exit.assert_called_once_with(2)

    @patch("ssl_checkup.exceptions.sys.exit")
    @patch("sys.stderr", new_callable=StringIO)
    def test_handle_socket_error_custom_port(self, mock_stderr, mock_exit):
        """Test socket error handling with custom port."""
        error = socket.gaierror("Name or service not known")

        handle_socket_error(error, "example.com", 8443, False)

        error_output = mock_stderr.getvalue()
        assert "Could not resolve or connect to 'example.com:8443'" in error_output
        mock_exit.assert_called_once_with(2)


class TestHandleSslError:
    """Test SSL error handling."""

    @patch("ssl_checkup.exceptions.sys.exit")
    @patch("sys.stderr", new_callable=StringIO)
    def test_handle_ssl_error_certificate_verify_failed(self, mock_stderr, mock_exit):
        """Test SSL error handling for certificate verification failure."""
        error = ssl.SSLError("certificate verify failed: CERTIFICATE_VERIFY_FAILED")

        handle_ssl_error(error, "example.com", 443, False)

        error_output = mock_stderr.getvalue()
        assert "SSL Certificate verification failed:" in error_output
        assert "If you want to bypass certificate validation" in error_output
        assert "--insecure" in error_output
        assert "-k" in error_output
        assert "ssl-checkup example.com:443 --insecure" in error_output
        mock_exit.assert_called_once_with(1)

    @patch("ssl_checkup.exceptions.sys.exit")
    @patch("sys.stderr", new_callable=StringIO)
    def test_handle_ssl_error_generic(self, mock_stderr, mock_exit):
        """Test SSL error handling for generic SSL error."""
        error = ssl.SSLError("SSL handshake failed")

        handle_ssl_error(error, "example.com", 443, False)

        error_output = mock_stderr.getvalue()
        assert "SSL Error:" in error_output
        assert "SSL handshake failed" in error_output
        mock_exit.assert_called_once_with(1)

    @patch("ssl_checkup.exceptions.sys.exit")
    @patch("ssl_checkup.exceptions.traceback.print_exc")
    @patch("sys.stderr", new_callable=StringIO)
    def test_handle_ssl_error_debug(self, mock_stderr, mock_traceback, mock_exit):
        """Test SSL error handling with debug enabled."""
        error = ssl.SSLError("SSL handshake failed")

        handle_ssl_error(error, "example.com", 443, True)

        error_output = mock_stderr.getvalue()
        assert "SSL Error:" in error_output
        assert "[DEBUG] SSL Exception:" in error_output
        assert "SSL handshake failed" in error_output
        mock_traceback.assert_called_once()
        mock_exit.assert_called_once_with(1)

    @patch("ssl_checkup.exceptions.sys.exit")
    @patch("sys.stderr", new_callable=StringIO)
    def test_handle_ssl_error_custom_port(self, mock_stderr, mock_exit):
        """Test SSL error handling with custom port."""
        error = ssl.SSLError("certificate verify failed: CERTIFICATE_VERIFY_FAILED")

        handle_ssl_error(error, "example.com", 8443, False)

        error_output = mock_stderr.getvalue()
        assert "ssl-checkup example.com:8443 --insecure" in error_output
        mock_exit.assert_called_once_with(1)

    @patch("ssl_checkup.exceptions.colored")
    @patch("ssl_checkup.exceptions.sys.exit")
    @patch("sys.stderr", new_callable=StringIO)
    def test_handle_ssl_error_colored_output(
        self, mock_stderr, mock_exit, mock_colored
    ):
        """Test SSL error handling with colored output."""
        mock_colored.side_effect = lambda text, color: f"[{color}]{text}[/{color}]"

        error = ssl.SSLError("certificate verify failed: CERTIFICATE_VERIFY_FAILED")

        handle_ssl_error(error, "example.com", 443, False)

        error_output = mock_stderr.getvalue()
        assert "[red]SSL Certificate verification failed:[/red]" in error_output
        assert "[yellow]--insecure[/yellow]" in error_output
        mock_exit.assert_called_once_with(1)


class TestHandleGeneralError:
    """Test general error handling."""

    @patch("ssl_checkup.exceptions.sys.exit")
    @patch("sys.stderr", new_callable=StringIO)
    def test_handle_general_error_basic(self, mock_stderr, mock_exit):
        """Test basic general error handling."""
        error = Exception("Something went wrong")

        handle_general_error(error, False)

        error_output = mock_stderr.getvalue()
        assert "Error: Something went wrong" in error_output
        mock_exit.assert_called_once_with(1)

    @patch("ssl_checkup.exceptions.sys.exit")
    @patch("ssl_checkup.exceptions.traceback.print_exc")
    @patch("sys.stderr", new_callable=StringIO)
    def test_handle_general_error_debug(self, mock_stderr, mock_traceback, mock_exit):
        """Test general error handling with debug enabled."""
        error = Exception("Something went wrong")

        handle_general_error(error, True)

        error_output = mock_stderr.getvalue()
        assert "Error: Something went wrong" in error_output
        assert "[DEBUG] Exception:" in error_output
        mock_traceback.assert_called_once()
        mock_exit.assert_called_once_with(1)

    @patch("ssl_checkup.exceptions.sys.exit")
    @patch("sys.stderr", new_callable=StringIO)
    def test_handle_general_error_value_error(self, mock_stderr, mock_exit):
        """Test general error handling with ValueError."""
        error = ValueError("Invalid input")

        handle_general_error(error, False)

        error_output = mock_stderr.getvalue()
        assert "Error: Invalid input" in error_output
        mock_exit.assert_called_once_with(1)

    @patch("ssl_checkup.exceptions.sys.exit")
    @patch("sys.stderr", new_callable=StringIO)
    def test_handle_general_error_type_error(self, mock_stderr, mock_exit):
        """Test general error handling with TypeError."""
        error = TypeError("Type mismatch")

        handle_general_error(error, False)

        error_output = mock_stderr.getvalue()
        assert "Error: Type mismatch" in error_output
        mock_exit.assert_called_once_with(1)


class TestColoredFallback:
    """Test colored function fallback when termcolor is not available."""

    @patch("ssl_checkup.exceptions.colored")
    def test_colored_fallback_usage(self, mock_colored):
        """Test that colored function is used when available."""
        mock_colored.return_value = "colored_text"

        # Import to trigger the colored function usage
        from ssl_checkup.exceptions import handle_ssl_error

        error = ssl.SSLError("certificate verify failed: CERTIFICATE_VERIFY_FAILED")

        with patch("ssl_checkup.exceptions.sys.exit"):
            with patch("sys.stderr", new_callable=StringIO):
                handle_ssl_error(error, "example.com", 443, False)

        # Check that colored was called
        assert mock_colored.call_count > 0

    def test_colored_fallback_function(self):
        """Test the colored fallback function when termcolor is not available."""
        # Test the fallback function directly
        from ssl_checkup.exceptions import colored

        result = colored("test", "red")
        assert result == "test"

        result = colored("test", None)
        assert result == "test"

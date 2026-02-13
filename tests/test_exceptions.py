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

    @patch("sys.stderr", new_callable=StringIO)
    def test_handle_keyboard_interrupt(self, mock_stderr):
        """Test keyboard interrupt handling."""
        code = handle_keyboard_interrupt()

        error_output = mock_stderr.getvalue()
        assert "Operation cancelled by user." in error_output
        assert code == 130


class TestHandleSocketError:
    """Test socket error handling."""

    @patch("sys.stderr", new_callable=StringIO)
    def test_handle_socket_error_basic(self, mock_stderr):
        """Test basic socket error handling."""
        error = socket.gaierror("Name or service not known")

        code = handle_socket_error(error, "example.com", 443, False)

        error_output = mock_stderr.getvalue()
        assert "Could not resolve or connect to 'example.com:443'" in error_output
        assert "Please check the hostname and your network connection" in error_output
        assert code == 10

    @patch("ssl_checkup.exceptions.traceback.print_exc")
    @patch("sys.stderr", new_callable=StringIO)
    def test_handle_socket_error_debug(self, mock_stderr, mock_traceback):
        """Test socket error handling with debug enabled."""
        error = socket.gaierror("Name or service not known")

        code = handle_socket_error(error, "example.com", 443, True)

        error_output = mock_stderr.getvalue()
        assert "Could not resolve or connect to 'example.com:443'" in error_output
        assert "[DEBUG] socket.gaierror:" in error_output
        assert "Name or service not known" in error_output
        mock_traceback.assert_called_once()
        assert code == 10


class TestHandleSslError:
    """Test SSL error handling."""

    @patch("sys.stderr", new_callable=StringIO)
    def test_handle_ssl_error_certificate_verify_failed(self, mock_stderr):
        """Test SSL error handling for certificate verification failure."""
        error = ssl.SSLError("certificate verify failed: CERTIFICATE_VERIFY_FAILED")

        code = handle_ssl_error(error, "example.com", 443, False)

        error_output = mock_stderr.getvalue()
        assert "SSL Certificate verification failed:" in error_output
        assert "If you want to bypass certificate validation" in error_output
        assert "--insecure" in error_output
        assert "-k" in error_output
        assert "ssl-checkup example.com:443 --insecure" in error_output
        assert code == 11

    @patch("sys.stderr", new_callable=StringIO)
    def test_handle_ssl_error_generic(self, mock_stderr):
        """Test SSL error handling for generic SSL error."""
        error = ssl.SSLError("SSL handshake failed")

        code = handle_ssl_error(error, "example.com", 443, False)

        error_output = mock_stderr.getvalue()
        assert "SSL Error:" in error_output
        assert "SSL handshake failed" in error_output
        assert code == 11


class TestHandleGeneralError:
    """Test general error handling."""

    @patch("sys.stderr", new_callable=StringIO)
    def test_handle_general_error_basic(self, mock_stderr):
        """Test basic general error handling."""
        error = Exception("Something went wrong")

        code = handle_general_error(error, False)

        error_output = mock_stderr.getvalue()
        assert "Error: Something went wrong" in error_output
        assert code == 12

    @patch("ssl_checkup.exceptions.traceback.print_exc")
    @patch("sys.stderr", new_callable=StringIO)
    def test_handle_general_error_debug(self, mock_stderr, mock_traceback):
        """Test general error handling with debug enabled."""
        error = Exception("Something went wrong")

        code = handle_general_error(error, True)

        error_output = mock_stderr.getvalue()
        assert "Error: Something went wrong" in error_output
        assert "[DEBUG] Exception:" in error_output
        mock_traceback.assert_called_once()
        assert code == 12

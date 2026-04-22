"""Tests for exceptions module."""

from io import StringIO
from unittest.mock import patch

from ssl_checkup.exceptions import handle_keyboard_interrupt


class TestHandleKeyboardInterrupt:
    """Test keyboard interrupt handling."""

    @patch("sys.stderr", new_callable=StringIO)
    def test_handle_keyboard_interrupt(self, mock_stderr):
        """Test keyboard interrupt handling."""
        code = handle_keyboard_interrupt()

        error_output = mock_stderr.getvalue()
        assert "Operation cancelled by user." in error_output
        assert code == 130

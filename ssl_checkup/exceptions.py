"""Exception handling and error management."""

import sys

EXIT_OPERATIONAL_ERROR = 10
EXIT_SSL_ERROR = 11
EXIT_GENERAL_ERROR = 12


def handle_keyboard_interrupt() -> int:
    """Handle Ctrl+C interruption."""
    print("\nOperation cancelled by user.", file=sys.stderr)
    return 130  # Standard exit code for Ctrl+C

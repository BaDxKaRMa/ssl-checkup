"""Exception handling and error management."""

import socket
import ssl
import sys
import traceback

# Handle optional termcolor dependency
try:
    from termcolor import colored
except ImportError:
    from typing import Iterable, Tuple, Union

    def colored(
        text: object,
        color: Union[str, Tuple[int, int, int], None] = None,
        on_color: Union[str, Tuple[int, int, int], None] = None,
        attrs: Union[Iterable[str], None] = None,
        *,
        no_color: Union[bool, None] = None,
        force_color: Union[bool, None] = None,
    ) -> str:
        return str(text)


def handle_keyboard_interrupt() -> None:
    """Handle Ctrl+C interruption."""
    print("\nOperation cancelled by user.", file=sys.stderr)
    sys.exit(130)  # Standard exit code for Ctrl+C


def handle_socket_error(
    e: socket.gaierror, hostname: str, port: int, debug: bool = False
) -> None:
    """Handle socket connection errors."""
    print(
        f"Could not resolve or connect to '{hostname}:{port}'. "
        "Please check the hostname and your network connection.",
        file=sys.stderr,
    )
    if debug:
        print("\n[DEBUG] socket.gaierror:", file=sys.stderr)
        print(e, file=sys.stderr)
        traceback.print_exc()
    sys.exit(2)


def handle_ssl_error(
    e: ssl.SSLError, hostname: str, port: int, debug: bool = False
) -> None:
    """Handle SSL connection errors."""
    error_msg = str(e)
    if "CERTIFICATE_VERIFY_FAILED" in error_msg:
        print(
            f"{colored('SSL Certificate verification failed:', 'red')} {e}",
            file=sys.stderr,
        )
        print(
            "If you want to bypass certificate validation, use the "
            + colored("--insecure", "yellow")
            + " or "
            + colored("-k", "yellow")
            + " flag:",
            file=sys.stderr,
        )
        print(
            f"  ssl-checkup {hostname}:{port} " + colored("--insecure", "yellow"),
            file=sys.stderr,
        )
    else:
        print(f"{colored('SSL Error:', 'red')} {e}", file=sys.stderr)

    if debug:
        print("\n[DEBUG] SSL Exception:", file=sys.stderr)
        print(e, file=sys.stderr)
        traceback.print_exc()
    sys.exit(1)


def handle_general_error(e: Exception, debug: bool = False) -> None:
    """Handle general exceptions."""
    print(f"Error: {e}", file=sys.stderr)
    if debug:
        print("\n[DEBUG] Exception:", file=sys.stderr)
        print(e, file=sys.stderr)
        traceback.print_exc()
    sys.exit(1)

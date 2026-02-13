import sys

"""Command line interface and argument parsing."""

import argparse

from . import __version__


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        description="Check and display SSL certificate details for a website.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "By default, displays a summary of the certificate including "
            "status, validity dates, issuer, subject, and SANs."
        ),
    )

    parser.add_argument(
        "website",
        nargs="?",
        help=("Website to check (e.g. example.com or " "example.com:443)"),
    )

    parser.add_argument(
        "--input",
        help="Read additional targets from file ('-' to read from stdin)",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of concurrent workers for --input mode (default: 4)",
    )

    parser.add_argument(
        "--insecure",
        "-k",
        action="store_true",
        help="Allow insecure server connections when using SSL (bypass "
        "certificate validation)",
    )

    parser.add_argument(
        "--version",
        action="store_true",
        help="Show version and exit",
    )

    parser.add_argument("--no-color", action="store_true", help="Disable color output")

    parser.add_argument(
        "--json-pretty",
        action="store_true",
        help="Pretty-print JSON output (requires --json)",
    )

    parser.add_argument(
        "--warn-days",
        type=int,
        default=30,
        help="Warning threshold in days before expiry (default: 30)",
    )

    parser.add_argument(
        "--critical-days",
        type=int,
        default=7,
        help="Critical threshold in days before expiry (default: 7)",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Socket timeout in seconds (default: 10)",
    )

    parser.add_argument(
        "--ip-version",
        choices=["auto", "4", "6"],
        default="auto",
        help="Prefer IPv4 or IPv6 when connecting (default: auto)",
    )

    output_mode_group = parser.add_mutually_exclusive_group()

    output_mode_group.add_argument(
        "-p",
        "--print-cert",
        action="store_true",
        help="Print the PEM certificate to stdout",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output for troubleshooting",
    )

    parser.add_argument(
        "--show-chain",
        action="store_true",
        help="Include certificate chain details in output",
    )

    output_mode_group.add_argument(
        "-i", "--issuer", action="store_true", help="Print only the issuer"
    )

    output_mode_group.add_argument(
        "-s", "--subject", action="store_true", help="Print only the subject"
    )

    output_mode_group.add_argument(
        "-a",
        "--san",
        action="store_true",
        help="Print only the Subject Alternative Names (SANs)",
    )
    output_mode_group.add_argument(
        "--json",
        action="store_true",
        help="Output certificate data as JSON",
    )

    return parser


def parse_website_arg(website: str) -> tuple[str, int]:
    """
    Parse website argument into hostname and port.

    Args:
        website: Website string (e.g., "example.com" or "example.com:8443")

    Returns:
        Tuple of (hostname, port)
    """
    hostname = website
    port = 443

    if website.startswith("["):
        end_bracket = website.find("]")
        if end_bracket == -1:
            raise ValueError("Invalid IPv6 format. Use [address]:port syntax.")

        hostname = website[1:end_bracket]
        remainder = website[end_bracket + 1 :]
        if remainder:
            if not remainder.startswith(":"):
                raise ValueError(
                    "Invalid IPv6 format. Use [address]:port syntax for custom ports."
                )
            port_str = remainder[1:]
            if not port_str:
                raise ValueError("Port is missing after ':'.")
            port = int(port_str)
    elif website.count(":") == 1:
        hostname, port_str = website.rsplit(":", 1)
        if not hostname:
            raise ValueError("Hostname cannot be empty.")
        if not port_str:
            raise ValueError("Port is missing after ':'.")
        port = int(port_str)
    elif ":" in website:
        # Unbracketed IPv6 address without a custom port.
        hostname = website

    if not hostname.strip():
        raise ValueError("Hostname cannot be empty.")
    if port < 1 or port > 65535:
        raise ValueError("Port must be between 1 and 65535.")
    return hostname, port


def handle_version_check(args: argparse.Namespace) -> bool:
    """
    Handle version argument and exit if requested.

    Args:
        args: Parsed arguments

    Returns:
        True if version was printed and program should exit
    """
    if args.version:
        print(f"ssl-checkup version {__version__}")
        sys.exit(0)
    return False


def validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """
    Validate arguments and show help if needed.

    Args:
        args: Parsed arguments
        parser: Argument parser instance
    """
    if not args.website and not getattr(args, "input", None):
        parser.print_help()
        sys.exit(1)

    if getattr(args, "json_pretty", False) and not getattr(args, "json", False):
        parser.error("--json-pretty requires --json")

    if getattr(args, "workers", 1) < 1:
        parser.error("--workers must be at least 1")

    if getattr(args, "warn_days", 0) < 0:
        parser.error("--warn-days must be >= 0")

    if getattr(args, "critical_days", 0) < 0:
        parser.error("--critical-days must be >= 0")

    if getattr(args, "critical_days", 0) > getattr(args, "warn_days", 0):
        parser.error("--critical-days cannot be greater than --warn-days")

    if getattr(args, "timeout", 0.0) <= 0:
        parser.error("--timeout must be > 0")

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
        "-i", "--issuer", action="store_true", help="Print only the issuer"
    )

    parser.add_argument(
        "-s", "--subject", action="store_true", help="Print only the subject"
    )

    parser.add_argument(
        "-a",
        "--san",
        action="store_true",
        help="Print only the Subject Alternative Names (SANs)",
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
    if ":" in website:
        hostname, port_str = website.split(":", 1)
        port = int(port_str)
    else:
        hostname = website
        port = 443
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
    if not args.website:
        parser.print_help()
        sys.exit(1)

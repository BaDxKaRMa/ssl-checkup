"""Main application logic and entry point."""

import socket
import ssl
import sys
import time
from typing import Any, Dict

from .cli import create_parser, handle_version_check, parse_website_arg, validate_args
from .connection import get_certificate
from .display import pretty_print_cert
from .exceptions import (
    handle_general_error,
    handle_keyboard_interrupt,
    handle_socket_error,
    handle_ssl_error,
)
from .formatting import DebugFormatter
from .parser import get_issuer_org, get_subject_cn, parse_pem_cert, parse_san


def print_single_field(cert: Dict[str, Any], field_type: str) -> None:
    """Print a single certificate field and exit."""
    if field_type == "issuer":
        value = get_issuer_org(cert)
    elif field_type == "subject":
        value = get_subject_cn(cert)
    elif field_type == "san":
        san_list = parse_san(cert)
        for name in san_list:
            print(name)
        return
    else:
        raise ValueError(f"Unknown field type: {field_type}")

    print(value if value else "N/A")


def main() -> None:
    """Main application entry point."""
    # Parse command line arguments
    parser = create_parser()
    args = parser.parse_args()

    # Handle version check
    handle_version_check(args)

    # Validate arguments
    validate_args(args, parser)

    # Parse website argument
    hostname, port = parse_website_arg(args.website)

    # Setup debug and color output
    debug = args.debug
    color_output = not args.no_color
    debug_formatter = DebugFormatter(color_output) if debug else None
    start_time = time.time() if debug else None

    try:
        # Handle PEM certificate printing
        if args.print_cert:
            pem = get_certificate(hostname, port, pem=True, insecure=args.insecure)
            print(pem)
            return

        # Get certificate information
        cert_info = get_certificate(hostname, port, insecure=args.insecure)

        # Handle debug output for connection details
        if debug and isinstance(cert_info, dict) and debug_formatter:
            debug_formatter.print_connection_details(
                hostname, port, cert_info, start_time
            )
            debug_formatter.print_cert_details(cert_info, args.insecure)

        # Extract certificate data
        if isinstance(cert_info, dict):
            cert = cert_info.get("cert")
        else:
            cert = cert_info

        if not isinstance(cert, dict):
            print("Error: Could not parse certificate details.", file=sys.stderr)
            sys.exit(1)

        # Handle single field output modes
        if args.issuer:
            print_single_field(cert, "issuer")
            return

        if args.subject:
            print_single_field(cert, "subject")
            return

        if args.san:
            if debug and debug_formatter:
                print("[DEBUG] SANs:")
                import pprint

                pprint.pprint(parse_san(cert))
            print_single_field(cert, "san")
            return

        # Store the cert that will be used for display
        display_cert = cert

        # Pretty print certificate information
        pretty_print_cert(
            cert,
            hostname,
            port,
            30,  # days_to_warn
            color_output,
            cert_info.get("pem") if isinstance(cert_info, dict) else None,
            args.insecure,
        )

        # Update display_cert if it was modified by pretty_print_cert due to PEM parsing
        if (
            not cert.get("notAfter")
            and args.insecure
            and isinstance(cert_info, dict)
            and cert_info.get("pem")
        ):
            pem_data = cert_info.get("pem")
            if pem_data:
                parsed_cert = parse_pem_cert(pem_data)
                if parsed_cert:
                    display_cert = parsed_cert

        # Debug query analysis
        if debug and debug_formatter:
            debug_formatter.print_query_analysis(hostname, display_cert)

    except KeyboardInterrupt:
        handle_keyboard_interrupt()
    except socket.gaierror as e:
        handle_socket_error(e, hostname, port, debug)
    except ssl.SSLError as e:
        handle_ssl_error(e, hostname, port, debug)
    except Exception as e:
        handle_general_error(e, debug)


if __name__ == "__main__":
    main()

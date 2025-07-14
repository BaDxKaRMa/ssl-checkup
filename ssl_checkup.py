#!/usr/bin/env python3
import argparse
import socket
import ssl
import sys
import textwrap
from datetime import datetime, timedelta

__version__ = "1.0.0"

try:
    from termcolor import colored
except ImportError:

    def colored(text, color=None):
        return text

    print(
        "\033[91m[ERROR]\033[0m: The 'termcolor' package is not installed.\n"
        "For best experience, install it with:\n"
        "  uv pip install termcolor\n  (or)\n  pip install termcolor\n"
        "Continuing without colored output...\n",
        file=sys.stderr,
    )


def get_certificate(hostname, port, pem=False, insecure=False):
    if insecure:
        context = ssl._create_unverified_context()
    else:
        context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=10) as sock:
        resolved_ip = sock.getpeername()[0]
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            tls_version = ssock.version()
            cipher = ssock.cipher()
            der_cert = ssock.getpeercert(binary_form=True)
            pem_cert = ssl.DER_cert_to_PEM_cert(der_cert) if der_cert else None
            cert = ssock.getpeercert()
            # Return all debug info for optional use
            return (
                {
                    "cert": cert,
                    "pem": pem_cert,
                    "resolved_ip": resolved_ip,
                    "tls_version": tls_version,
                    "cipher": cipher,
                }
                if not pem
                else pem_cert
            )


def parse_san(cert):
    san = []
    for ext in cert.get("subjectAltName", []):
        if ext[0] == "DNS":
            san.append(ext[1])
    return san


def pretty_print_cert(cert, hostname, port, days_to_warn, color_output):
    not_after = cert.get("notAfter")
    not_before = cert.get("notBefore")
    issuer = dict(x[0] for x in cert.get("issuer", []))
    subject = dict(x[0] for x in cert.get("subject", []))
    san = parse_san(cert)

    # Parse expiration
    expire_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    now = datetime.utcnow()
    days_left = (expire_date - now).days

    # Color logic
    # Color setup
    def cfield(key):
        return colored(key, "white") if color_output else key

    def cissuer(val):
        return colored(val, "magenta") if color_output else val

    def csubject(val, highlight=False):
        if color_output:
            return colored(val, "cyan") if highlight else colored(val, "blue")
        return val

    def csan(val, highlight=False):
        if color_output:
            return colored(val, "cyan") if highlight else colored(val, "blue")
        return val

    def cplain(val):
        return colored(val, "white") if color_output else val

    if color_output:
        if days_left < 0:
            status = colored("EXPIRED", "red")
        elif days_left <= 30:
            status = colored(f"WARNING ({days_left} days left)", "yellow")
        else:
            status = colored(f"VALID ({days_left} days left)", "green")
    else:
        if days_left < 0:
            status = "EXPIRED"
        elif days_left <= 30:
            status = f"WARNING ({days_left} days left)"
        else:
            status = f"VALID ({days_left} days left)"

    # Determine subject and issuer
    issuer_val = issuer.get("organizationName", issuer.get("O", "N/A"))
    subject_val = subject.get("commonName", subject.get("CN", "N/A"))

    # Determine which SAN matches query
    query = hostname.lower()
    subject_match = subject_val.lower() == query

    def cquery(val):
        return colored(val, "cyan") if color_output else val

    print(f"\n{cfield('Certificate for:')} {cquery(f'{hostname}:{port}')}")
    print(f"  {cfield('Status:')} {status}")
    print(f"  {cfield('Not Before:')} {cplain(not_before)}")
    print(f"  {cfield('Not After:')}  {cplain(not_after)}")
    print(f"  {cfield('Issuer:')}     {cissuer(issuer_val)}")
    print(f"  {cfield('Subject:')}    {csubject(subject_val, highlight=subject_match)}")
    if san:
        print(f"  {cfield('SANs:')}")
        for name in san:
            highlight = name.lower() == query or (
                subject_match and name.lower() == subject_val.lower()
            )
            print(f"    - {csan(name, highlight=highlight)}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Check and display SSL certificate details for a website.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="By default, displays a summary of the certificate including status, validity dates, issuer, subject, and SANs.",
    )
    parser.add_argument(
        "website",
        nargs="?",
        help="Website to check (e.g. example.com or example.com:443)",
    )
    parser.add_argument(
        "--insecure",
        "-k",
        action="store_true",
        help="Allow insecure server connections when using SSL (bypass certificate validation)",
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

    args = parser.parse_args()

    if args.version:
        print(f"ssl-checkup version {__version__}")
        sys.exit(0)

    if not args.website:
        parser.print_help()
        sys.exit(1)

    if ":" in args.website:
        hostname, port = args.website.split(":", 1)
        port = int(port)
    else:
        hostname = args.website
        port = 443

    debug = False
    import pprint
    import time

    try:
        color_output = not args.no_color
        debug = args.debug
        start_time = time.time() if debug else None
        if args.print_cert:
            pem = get_certificate(hostname, port, pem=True, insecure=args.insecure)
            print(pem)
            return
        cert_info = get_certificate(hostname, port, insecure=args.insecure)
        # If get_certificate returns just the PEM (for --print-cert), cert_info is a string
        if isinstance(cert_info, dict):
            if debug:

                def dheader(text):
                    if color_output:
                        return (
                            "\n["
                            + colored("DEBUG", "red")
                            + "]"
                            + text.split("]", 1)[-1]
                        )
                    return "\n" + text

                print(dheader("[DEBUG] Connection details:"))
                print(f"  Hostname: {hostname}")
                print(f"  Port: {port}")
                print(f"  Resolved IP: {cert_info.get('resolved_ip', 'N/A')}")
                print(f"  TLS Version: {cert_info.get('tls_version', 'N/A')}")
                print(f"  Cipher: {cert_info.get('cipher', 'N/A')}")
                if start_time is not None:
                    print(
                        f"  Time to connect/fetch: {time.time() - start_time:.3f} seconds"
                    )
                print(dheader("[DEBUG] Raw certificate dict:"))
                pprint.pprint(cert_info.get("cert"))
                print(dheader("[DEBUG] PEM certificate:"))
                print(cert_info.get("pem"))
            cert = cert_info.get("cert")
        else:
            cert = cert_info
        if not isinstance(cert, dict):
            print("Error: Could not parse certificate details.", file=sys.stderr)
            sys.exit(1)
        if args.issuer:
            issuer = cert["issuer"] if "issuer" in cert else []
            org = None
            for tup in issuer:
                for k, v in tup:
                    if k in ("organizationName", "O"):
                        org = v
                        break
                if org:
                    break
            print(org if org else "N/A")
            return
        if args.subject:
            subject = cert["subject"] if "subject" in cert else []
            cn = None
            for tup in subject:
                for k, v in tup:
                    if k in ("commonName", "CN"):
                        cn = v
                        break
                if cn:
                    break
            print(cn if cn else "N/A")
            return
        if args.san:
            san = parse_san(cert)
            if debug:
                print("[DEBUG] SANs:")
                pprint.pprint(san)
            for name in san:
                print(name)
            return
        pretty_print_cert(cert, hostname, port, 30, color_output)
        if debug:

            def dheader(text):
                if color_output:
                    return "[" + colored("DEBUG", "red") + "]" + text.split("]", 1)[-1]
                return text

            print("\n" + dheader("[DEBUG] Query:") + f" {hostname}")
            subject_val = dict(x[0] for x in cert.get("subject", [])).get(
                "commonName", None
            )
            print(dheader("[DEBUG] Subject:") + f" {subject_val}")
            san = parse_san(cert)
            print(dheader("[DEBUG] SANs:") + f" {san}")
            matches = [name for name in san if name.lower() == hostname.lower()]
            if subject_val and subject_val.lower() == hostname.lower():
                print(dheader("[DEBUG] Query matches subject."))
            if matches:
                print(dheader(f"[DEBUG] Query matches SAN(s): {matches}"))
            else:
                print(dheader("[DEBUG] Query does not match any SAN."))
    except socket.gaierror as e:
        print(
            f"Could not resolve or connect to '{hostname}:{port}'. Please check the hostname and your network connection.",
            file=sys.stderr,
        )
        if "debug" in locals() and debug:
            import traceback

            print("\n[DEBUG] socket.gaierror:", file=sys.stderr)
            print(e, file=sys.stderr)
            traceback.print_exc()
        sys.exit(2)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if "debug" in locals() and debug:
            import traceback

            print("\n[DEBUG] Exception:", file=sys.stderr)
            print(e, file=sys.stderr)
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

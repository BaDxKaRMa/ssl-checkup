"""Main application logic and entry point."""

import json
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Dict

from .cli import create_parser, handle_version_check, parse_website_arg, validate_args
from .connection import get_certificate
from .display import pretty_print_cert
from .exceptions import (
    EXIT_OPERATIONAL_ERROR,
    handle_general_error,
    handle_keyboard_interrupt,
    handle_socket_error,
    handle_ssl_error,
)
from .formatting import DebugFormatter
from .parser import get_issuer_org, get_subject_cn, parse_pem_cert, parse_san

STATUS_VALID = "valid"
STATUS_WARNING = "warning"
STATUS_CRITICAL = "critical"
STATUS_EXPIRED = "expired"


def _arg(args: Any, name: str, default: Any) -> Any:
    """Read argparse values safely, including mocked test objects."""
    try:
        return vars(args).get(name, default)
    except TypeError:
        return getattr(args, name, default)


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


def _is_policy_mode(args: Any) -> bool:
    return not (
        _arg(args, "print_cert", False)
        or _arg(args, "issuer", False)
        or _arg(args, "subject", False)
        or _arg(args, "san", False)
    )


def _resolve_display_cert(
    cert: Dict[str, Any], cert_info: Dict[str, Any], insecure: bool
) -> Dict[str, Any]:
    """Resolve certificate details, with PEM fallback when insecure mode is used."""
    if cert.get("notAfter"):
        return cert

    if insecure:
        pem_data = cert_info.get("pem")
        if pem_data:
            parsed_cert = parse_pem_cert(pem_data)
            if parsed_cert:
                return parsed_cert

    return cert


def _calculate_status(
    cert: Dict[str, Any], warn_days: int, critical_days: int
) -> Dict[str, Any]:
    """Calculate expiry status and days left from certificate dates."""
    not_after = cert.get("notAfter")
    if not not_after:
        raise ValueError("Could not determine certificate expiration date (notAfter)")

    expire_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    days_left = (expire_date - datetime.utcnow()).days

    if days_left < 0:
        status = STATUS_EXPIRED
    elif days_left <= critical_days:
        status = STATUS_CRITICAL
    elif days_left <= warn_days:
        status = STATUS_WARNING
    else:
        status = STATUS_VALID

    return {"days_left": days_left, "status": status}


def _status_to_exit_code(status: str) -> int:
    if status in (STATUS_EXPIRED, STATUS_CRITICAL):
        return 2
    if status == STATUS_WARNING:
        return 1
    return 0


def _iter_input_targets(input_path: str) -> list[str]:
    """Read raw targets from input source."""
    if input_path == "-":
        lines = sys.stdin.read().splitlines()
    else:
        with open(input_path, encoding="utf-8") as handle:
            lines = handle.readlines()

    targets: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(line)
    return targets


def _collect_targets(args: Any) -> list[tuple[str, int, str]]:
    """Collect and parse all targets from CLI args and optional input."""
    raw_targets: list[str] = []
    website = _arg(args, "website", None)
    if website:
        raw_targets.append(website)

    input_path = _arg(args, "input", None)
    if input_path:
        raw_targets.extend(_iter_input_targets(input_path))

    targets: list[tuple[str, int, str]] = []
    for raw_target in raw_targets:
        hostname, port = parse_website_arg(raw_target)
        targets.append((hostname, port, raw_target))

    return targets


def _build_json_result(
    hostname: str,
    port: int,
    raw_target: str,
    cert_info: Dict[str, Any],
    cert: Dict[str, Any],
    args: Any,
) -> Dict[str, Any]:
    """Build JSON-serializable result payload."""
    issuer = get_issuer_org(cert)
    subject = get_subject_cn(cert)
    san = parse_san(cert)

    result: Dict[str, Any] = {
        "target": raw_target,
        "hostname": hostname,
        "port": port,
        "resolved_ip": cert_info.get("resolved_ip"),
        "tls_version": cert_info.get("tls_version"),
        "cipher": cert_info.get("cipher"),
        "insecure": bool(_arg(args, "insecure", False)),
        "issuer": issuer,
        "subject": subject,
        "san": san,
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "warning_days": _arg(args, "warn_days", 30),
        "critical_days": _arg(args, "critical_days", 7),
    }

    if _is_policy_mode(args):
        status_data = _calculate_status(
            cert,
            warn_days=_arg(args, "warn_days", 30),
            critical_days=_arg(args, "critical_days", 7),
        )
        result.update(status_data)

    return result


def _run_target(hostname: str, port: int, raw_target: str, args: Any) -> Dict[str, Any]:
    """Run one target check and return structured result."""
    try:
        cert_info = get_certificate(
            hostname,
            port,
            insecure=bool(_arg(args, "insecure", False)),
            timeout=float(_arg(args, "timeout", 10.0)),
            ip_version=str(_arg(args, "ip_version", "auto")),
        )

        if not isinstance(cert_info, dict):
            raise ValueError("Could not parse certificate details.")

        cert = cert_info.get("cert")
        if not isinstance(cert, dict):
            raise ValueError("Could not parse certificate details.")

        display_cert = _resolve_display_cert(
            cert,
            cert_info,
            insecure=bool(_arg(args, "insecure", False)),
        )

        result = _build_json_result(
            hostname, port, raw_target, cert_info, display_cert, args
        )
        result["cert"] = display_cert
        result["pem"] = cert_info.get("pem")
        return result
    except Exception as exc:
        error_kind = "general_error"
        if isinstance(exc, socket.gaierror):
            error_kind = "socket_error"
        elif isinstance(exc, ssl.SSLError):
            error_kind = "ssl_error"

        return {
            "target": raw_target,
            "hostname": hostname,
            "port": port,
            "error": {
                "kind": error_kind,
                "message": str(exc),
            },
        }


def _print_json(data: Any, pretty: bool) -> None:
    """Print JSON payload."""
    if pretty:
        print(json.dumps(data, indent=2, sort_keys=True, default=str))
    else:
        print(json.dumps(data, separators=(",", ":"), default=str))


def _print_target_human(
    result: Dict[str, Any], args: Any, is_batch: bool = False
) -> None:
    """Print one target result in human-readable mode."""
    if result.get("error"):
        err = result["error"]
        print(
            f"Error for {result['target']}: {err.get('kind')} - {err.get('message')}",
            file=sys.stderr,
        )
        return

    cert = result["cert"]
    hostname = result["hostname"]
    port = result["port"]

    if is_batch:
        print(f"==> {result['target']}")

    if _arg(args, "print_cert", False):
        print(result.get("pem") or "")
    elif _arg(args, "issuer", False):
        print_single_field(cert, "issuer")
    elif _arg(args, "subject", False):
        print_single_field(cert, "subject")
    elif _arg(args, "san", False):
        print_single_field(cert, "san")
    else:
        pretty_print_cert(
            cert,
            hostname,
            port,
            _arg(args, "warn_days", 30),
            not bool(_arg(args, "no_color", False)),
            result.get("pem"),
            bool(_arg(args, "insecure", False)),
        )


def _batch_exit_code(results: list[Dict[str, Any]], args: Any) -> int:
    """Derive a batch exit code based on errors and status policy."""
    if any(result.get("error") for result in results):
        return EXIT_OPERATIONAL_ERROR

    if not _is_policy_mode(args):
        return 0

    worst = 0
    for result in results:
        status = result.get("status", STATUS_VALID)
        worst = max(worst, _status_to_exit_code(status))
    return worst


def _run_batch(targets: list[tuple[str, int, str]], args: Any) -> int:
    """Run checks for all targets using thread pool."""
    workers = int(_arg(args, "workers", 4))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(_run_target, hostname, port, raw_target, args)
            for hostname, port, raw_target in targets
        ]
        results = [future.result() for future in futures]

    if _arg(args, "json", False):
        payload: Any = results
        if len(results) == 1 and not _arg(args, "input", None):
            payload = results[0]
        _print_json(payload, pretty=bool(_arg(args, "json_pretty", False)))
    else:
        for index, result in enumerate(results):
            _print_target_human(result, args, is_batch=len(results) > 1)
            if len(results) > 1 and index < len(results) - 1:
                print()

    return _batch_exit_code(results, args)


def _run_single(hostname: str, port: int, raw_target: str, args: Any) -> int:
    """Run one target with classic exception handlers."""
    debug = bool(_arg(args, "debug", False))
    color_output = not bool(_arg(args, "no_color", False))
    debug_formatter = DebugFormatter(color_output) if debug else None
    start_time = time.time() if debug else None

    try:
        if _arg(args, "print_cert", False):
            pem = get_certificate(
                hostname,
                port,
                pem=True,
                insecure=bool(_arg(args, "insecure", False)),
                timeout=float(_arg(args, "timeout", 10.0)),
                ip_version=str(_arg(args, "ip_version", "auto")),
            )
            print(pem)
            return 0

        cert_info = get_certificate(
            hostname,
            port,
            insecure=bool(_arg(args, "insecure", False)),
            timeout=float(_arg(args, "timeout", 10.0)),
            ip_version=str(_arg(args, "ip_version", "auto")),
        )

        if debug and isinstance(cert_info, dict) and debug_formatter:
            debug_formatter.print_connection_details(
                hostname,
                port,
                cert_info,
                start_time,
            )
            debug_formatter.print_cert_details(
                cert_info, bool(_arg(args, "insecure", False))
            )

        if isinstance(cert_info, dict):
            cert = cert_info.get("cert")
        else:
            cert = cert_info

        if not isinstance(cert, dict):
            print("Error: Could not parse certificate details.", file=sys.stderr)
            return 1

        display_cert = _resolve_display_cert(
            cert,
            cert_info if isinstance(cert_info, dict) else {},
            insecure=bool(_arg(args, "insecure", False)),
        )

        if _arg(args, "json", False):
            if not isinstance(cert_info, dict):
                raise ValueError("Could not parse certificate details.")
            json_result = _build_json_result(
                hostname,
                port,
                raw_target,
                cert_info,
                display_cert,
                args,
            )
            _print_json(json_result, pretty=bool(_arg(args, "json_pretty", False)))
        elif _arg(args, "issuer", False):
            print_single_field(display_cert, "issuer")
        elif _arg(args, "subject", False):
            print_single_field(display_cert, "subject")
        elif _arg(args, "san", False):
            if debug and debug_formatter:
                print("[DEBUG] SANs:")
                import pprint

                pprint.pprint(parse_san(display_cert))
            print_single_field(display_cert, "san")
        else:
            pretty_print_cert(
                display_cert,
                hostname,
                port,
                _arg(args, "warn_days", 30),
                color_output,
                cert_info.get("pem") if isinstance(cert_info, dict) else None,
                bool(_arg(args, "insecure", False)),
            )

        if debug and debug_formatter:
            debug_formatter.print_query_analysis(hostname, display_cert)

        if _is_policy_mode(args):
            status_data = _calculate_status(
                display_cert,
                warn_days=_arg(args, "warn_days", 30),
                critical_days=_arg(args, "critical_days", 7),
            )
            return _status_to_exit_code(status_data["status"])

        return 0

    except KeyboardInterrupt:
        handle_keyboard_interrupt()
        return 0
    except socket.gaierror as e:
        handle_socket_error(e, hostname, port, debug)
        return 0
    except ssl.SSLError as e:
        handle_ssl_error(e, hostname, port, debug)
        return 0
    except Exception as e:
        handle_general_error(e, debug)
        return 0

    return 1


def main() -> None:
    """Main application entry point."""
    parser = create_parser()
    args = parser.parse_args()

    handle_version_check(args)
    validate_args(args, parser)

    try:
        targets = _collect_targets(args)
    except ValueError as exc:
        parser.error(f"Invalid website argument: {exc}")
    except OSError as exc:
        parser.error(f"Could not read input targets: {exc}")

    if not targets:
        parser.error("No valid targets were provided")

    if len(targets) == 1 and not _arg(args, "input", None):
        hostname, port, raw_target = targets[0]
        exit_code = _run_single(hostname, port, raw_target, args)
    else:
        exit_code = _run_batch(targets, args)

    if exit_code != 0:
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
